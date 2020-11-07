#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
import sys
import pyipmi
import pyipmi.interfaces
import socket
import subprocess
from shlex import split
from tinydb import TinyDB, Query
from tinydb.operations import delete
from copy import copy
from pandas import DataFrame
from datetime import datetime, timedelta
import getpass
from pathlib import Path
from re import match

DBFILE = '/usr/local/tm/tmdb.json'
TFTPBOOT = '/var/lib/tftpboot'
namehelp = 'hostname (e.g., n04)'
dtfmt = '%d/%m/%y'
MAXDAYS = 14

class TmMsg(object):
    def empty_db():
        return 'empty database'
    def not_in_inventory(node):
        return '{}: not in inventory'.format(node)
    def non_root_clean():
        return 'clean command must be run by root'
    def invalid_node(node):
        return '{}: invalid node'.format(node)
    def not_reserved(node):
        return '{}: not reserved'.format(node)
    def need_owner_or_root(node):
        return '{}: need reservation or to be root'.format(node)
    def in_use(node, user):
        return '{}: in use by {}'.format(node, user)
    def root_reserve():
        return 'root cannot reserve nodes'
    def invalid_date_format():
        return 'date format must be dd/mm/yy'
    def invalid_date():
        return  'date must be on or later than today'
    def shrinked_date(days):
        return 'set {} days of the maximum duration'.format(days)
    def symlink_fail(node):
        return '{}: failed to create symlink'.format(node)
    def restore_fail(node, mac):
        return '{}: cannot restore symlink for {}'.format(node, mac)
    def success(node, ops):
        return '{}: {} success'.format(node, ops)
    def no_host(node):
        return '{}: no network name - check system configuration'.format(node)
    def non_default_ipmi(node, addr, def_addr):
        return '{}: ipmi addr {} differs from the defaule one {}'.format(
                node, addr, def_addr)
    def reachable(node):
        return 'reachable'
    def unreachable(node):
        return 'unreachable'
    def no_dnsmasq_conf(node):
        return '{}: not in /etc/dnsmasq.conf'.format(node)
    def fail2(node, cmd):
        return '{}: failed in {}'.format(node, cmd)
    def no_db(node):
        return '{} is not in the db'.format(node)
    def opaque(m):
        return '{}'.format(m)
    def df(d):
        return '{}'.format(d)
    def fail_restart(node):
        return '{}: failed to restart, perhaps the power is off'.format(node)

class Tm(object):
    def __init__(self, argv, dbfile=DBFILE, tftpboot=TFTPBOOT, test=False):
        self.output = ''
        self.tftpboot = tftpboot
        self.db = TinyDB(dbfile)
        self.ipmi_addr_off = 100
        self.addrs = ('mac', 'ip', 'ipmiaddr', 'ipmipass')
        self.devices = ('disk', 'nic', 'accel')
        self.user = getpass.getuser()
        self.test = test

        parser = ArgumentParser(description="tm - testbed management tool",
                usage='tm [-h] COMMAND <args>')
        parser.add_argument('command', metavar='COMMAND',
                choices=['inventory', 'power', 'console', 'reservation'],
                help='{inventory|power|console}')
        args = parser.parse_args(argv[1:2])
        getattr(self, args.command)(argv)

    def reservation(self, argv):
        parser = ArgumentParser(description="tm-reservation - node reservation",
                usage='tm reservation COMMAND [<args>]')
        subparsers = parser.add_subparsers(title='COMMAND')
        cmds = ('reserve', 'update', 'release', 'show', 'clean')
        for cmd in cmds:
            p = subparsers.add_parser(cmd,
                    usage='tm reservation {} <args>'.format(cmd))
            if cmd == 'show':
                p.add_argument('--node', type=str, help=namehelp)
            elif cmd == 'clean':
                p.add_argument('--noexpire', action='store_true',
                        help='release nodes regardless of expiration')
            else:
                p.add_argument('node', type=str, help=namehelp)
            if cmd == 'reserve' or cmd == 'update':
                p.add_argument('expire', type=str, help='ddmmyy')
            p.set_defaults(func=cmd)
        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'): # XXX
            parser.print_help()
            return

        if args.func == 'show':
            ans = self.get_db(node=args.node)
            if not ans:
                if args.node:
                    self.pr_msg(TmMsg.no_db(args.node))
                else:
                    self.pr_msg(TmMsg.empty_db())
                return
            self.pr_msg(DataFrame.from_dict(ans).reindex(
                columns=('node', 'user', 'expire')))
            return

        if args.func == 'clean':
            if self.user != 'root':
                self.pr_msg(TmMsg.non_root_clean())
                return
            today = datetime.now().date()
            ans = self.get_db()
            for v in ans:
                if not 'user' in v:
                    continue
                if (args.noexpire or
                    today > datetime.strptime(v['expire'], dtfmt).date()):
                    if not self.test:
                        self.power(split('tm power poweroff {}'.format(v['node'])))
                    self.reset_node(v['node'], v['mac'])
            return

        r = self.db.get(Query().node == args.node)
        if not r:
            self.pr_msg(TmMsg.invalid_node(args.node))
            return
        elif args.func == 'reserve':
            if 'user' in r:
                self.pr_msg(TmMsg.in_use(args.node, r['user']))
                return
            elif self.user == 'root':
                self.pr_msg(TmMsg.root_reserve(args.node))
                return
        elif args.func == 'release' or args.func == 'update':
            if not self.owner_or_root(args.node):
                return
        elif args.func == 'clean':
            if self.user != 'root':
                self.pr_msg(TmMsg.non_root_clean())

        if args.func == 'reserve' or args.func == 'update':
            try:
                dt = datetime.strptime(args.expire, dtfmt).date()
            except(ValueError):
                self.pr_msg(TmMsg.invalid_date_format())
                return
            today = datetime.now().date()
            if dt < today:
                self.pr_msg(TmMsg.invalid_date())
                return
            else:
                latest = (datetime.now() + timedelta(days=MAXDAYS)).date()
                if dt > latest:
                    dt = latest
                    self.pr_msg(TmMsg.shrinked_date(MAXDAYS))

            if args.func == 'reserve':
                if not self.set_loader(r['mac'], self.user, args.node):
                    self.pr_msg(TmMsg.symlink_fail(args.node))
                    return

            self.db.update({'user': getpass.getuser(),
                'expire': dt.strftime(dtfmt)}, Query().node == args.node)
        else:
            if not self.test:
                self.power(split('tm power poweroff {}'.format(args.node)))
            self.reset_node(args.node, r['mac'])
        self.pr_msg(TmMsg.success(args.node, args.func))

    def inventory(self, argv):
        parser = ArgumentParser(description="tm-inventory - "
            "node metadata management", usage='tm inventory COMMAND [<args>]')
        subparsers = parser.add_subparsers(title='COMMAND')

        for cmd in ('show', 'test'):
            p = subparsers.add_parser(cmd,
                    usage='tm inventory {} [<args>]'.format(cmd))
            p.add_argument('--node', type=str, help=namehelp)
            if cmd == 'show':
                p.add_argument('--addrs', action='store_true',
                        help='management addresses') 
                p.add_argument('--devices', action='store_true',
                        help='I/O peripherals') 
            p.set_defaults(func=cmd)
        delete = subparsers.add_parser('delete')
        delete.add_argument('node', type=str, help=namehelp)
        delete.set_defaults(func='delete')

        t = True
        f = False
        for cmd in ('add', 'update'):
            p = subparsers.add_parser(cmd)
            lm = lambda o, t, r, h: p.add_argument(o, type=t, required=r, help=h)
            lm('--mac', str, t, 'MAC addr (e.g., 00:00:00:00:00:00)')
            lm('--ip', str, t, 'IPv4 addr (e.g., 192.168.0.2)')
            lm('--ipmipass', str, t, 'IPMI user,pass (e.g., ADMIN,ADMIN)')
            lm('--cpu', str, t, 'CPU (e.g., Intel Xeon E3-1220v3)')
            lm('--ram', int, t, 'RAM in GB (e.g., 64)')
            lm('--nic', str, t, '(non-boot) NIC (e.g., Intel X520-SR2)')
            lm('--disk', str, f, 'Disk (e.g., Samsung Evo 870 256GB)')
            lm('--accel', str, f, 'Accelerator (e.g., ZOTAC GeForce GTX 1070)')
            lm('--note', str, f, 'Note (e.g., PCIe slot 1 is broken)')
            lm('--ipmiaddr', str, f, 'IPMI address (e.g., if not ip+100)')
            t = False
            p.add_argument('node', type=str, help=namehelp)
            p.set_defaults(func=cmd)

        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'): # XXX
            parser.print_help()
            return
        if args.func != 'add' and hasattr(args, 'node'):
            if args.node and None in self.get_addrs(args.node):
                self.pr_msg(TmMsg.invalid_node(args.node))
                return

        if args.func == 'add' or args.func == 'update':

            if args.mac:
                if not self.is_mac(args.mac):
                    self.pr_msg(TmMsg.no_mac(args.node, args.mac))
                    return
            if args.ip:
                if not self.is_ipaddr(args.ip):
                    self.pr_msg(TmMsg.no_mac(args.node, args.ip))
                    return
            if args.ipmiaddr:
                if not self.is_ipaddr(args.ipmiaddr):
                    self.pr_msg(TmMsg.no_mac(args.node, args.ipmiaddr))
                    return
            if args.ipmipass:
                if not self.is_ipmipass(args.ipmipass):
                    self.pr_msg(TmMsg.no_ipmi_pass(args.node, args.ipmipass))
                    return

            d = copy(vars(args))
            del d['func']
            if args.func == 'update':
                del d['node']
                self.db.update(d, Query().node == args.node)
            else:
                self.db.insert(d)
            self.pr_msg(TmMsg.success(args.node, args.func))

        elif args.func == 'show' or args.func == 'test':
            ans = self.get_db(node=args.node)
            if ans is None:
                if args.node:
                    self.pr_msg(TmMsg.no_db(args.node))
                else:
                    self.pr_msg(TmMsg.empty_db())
            elif args.func == 'show':
                df = DataFrame.from_dict(ans)
                cls = list(df.columns)
                reorders = ('node', 'mac', 'ip', 'ipmiaddr')
                for i, r in enumerate(reorders):
                    cls.remove(r)
                    cls.insert(i, r)
                if args.func == 'show':
                    for a in ('addrs', 'devices'):
                        if not getattr(args, a):
                            cls = [c for c in cls if c not in getattr(self, a)]
                self.pr_msg(df.reindex(columns=cls))
            else:
                for node in ans:
                    # test dns
                    try:
                        addr = socket.gethostbyname(node['node'])
                    except(socket.gaierror):
                        self.pr_msg(TmMsg.no_host(node['node']))
                        return

                    # compare with those registered to inventory
                    msg = (node['node'] +
                            ': Network address {} {} inventory one {}')
                    m = 'unmatches' if addr != node['ip'] else 'matches'
                    print(msg.format(addr, m, node['ip']))

                    if self.def_ipmi_addr(addr) != node['ipmiaddr']:
                        self.pr_msg(TmMsg.non_default_ipmi(
                            self.def_ipmi_addr(addr), node['ipmiaddr']))

                    # test ipmi
                    cmd = 'ping -c 2 {}'.format(node['ipmiaddr'])
                    msg = node['node'] + ': IPMI {} {}'
                    try:
                        subprocess.call(split(cmd),
                                stdout=subprocess.DEVNULL)
                        print(msg.format(node['ipmiaddr'], 'reachable'))
                    except(OSError):
                        print(msg.format(node['ipmiaddr'], 'unreachable'))

                    # test loader
                    loaderpath = Path(self.tftpboot)/'pxelinux.cfg'
                    cmd = 'ls {}'.format(loaderpath)
                    msg = node['node'] + ': loader {} {} in ' + str(loaderpath)
                    try:
                        res = subprocess.check_output(split(cmd))
                    except(subprocess.CalledProcessError) as e:
                        self.pr_msg(TmMsg.fail2(node['node'], cmd))
                        return
                    files = []
                    for f in res.decode().split('\n')[0:-1]:
                        files.append(f.lstrip('01-').replace('-', ':'))
                    print(msg.format(node['mac'],
                        'found' if node['mac'] in files else 'not found'))

                    # test /etc/dnsmasq.conf
                    cmd = ("cat /etc/dnsmasq.conf | grep ^dhcp-host= "
                           "| cut -d' ' -f1 | cut -d'=' -f2")
                    try:
                        res = subprocess.getoutput(cmd)
                    except(subprocess.CalledProcessError):
                        self.pr_msg(TmMsg.fail2(node['node'], cmd))
                    for line in res.split('\n'):
                        mac, ip, name = line.split(',')
                        if node['node'] == name:
                            if node['mac'] == mac and node['ip'] == ip:
                                print('{}: MAC and IP address found in '
                                      '/etc/dnsmasq.conf'.format(node['node']))
                                break
                            if node['mac'] != mac:
                                print('{}: inventory {} registered {}'.format(
                                    node['mac'], mac))
                            if node['ip'] != ip:
                                print('{}: inventory {} registered {}'.format(
                                    node['ip'], ip))
                            break
                    else:
                        self.pr_msg(TmMsg.no_dnsmasq_conf(node['node']))
                        return

        elif args.func == 'delete':
            r = self.db.get(Query().node == args.node)
            if r:
                self.db.remove(doc_ids=[r.doc_id,])
            else:
                self.pr_msg(TmMsg.no_db(args.node))

    def power(self, argv):
        parser = ArgumentParser(description="tm-power - power management",
                    usage='tm power COMMAND <node>')
        parser.add_argument('command', metavar='COMMAND', type=str,
        choices=['status', 'poweron', 'poweroff', 'restart'],
                help='{status|poweron|poweroff|restart}')
        parser.add_argument('node', type=str, help=namehelp)
        args = parser.parse_args(argv[2:])

        if args.command != 'status':
            if not self.owner_or_root(args.node, needuser=False):
                return
        addr = self.get_addrs(args.node)[1]
        if not addr:
            self.pr_msg(TmMsg.not_in_inventory(args.node))
            return
        interface = pyipmi.interfaces.create_interface('ipmitool',
                interface_type='lanplus')
        ipmi = pyipmi.create_connection(interface)
        ipmi.target = pyipmi.Target(0x0)
        ipmi.session.set_session_type_rmcp(addr)
        ipmi.session.establish()
        r = None
        # Dell and Supermicro default user/pass
        for u, p in [('root', 'calvin'), ('ADMIN', 'ADMIN')]:
            ipmi.session.set_auth_type_user(u, p)
            try:
                if args.command == 'status':
                    r = ipmi.get_chassis_status()
                elif args.command == 'poweroff':
                    r = ipmi.chassis_control_power_down()
                elif args.command == 'poweron':
                    r = ipmi.chassis_control_power_up()
                elif args.command == 'restart':
                    try:
                        r = ipmi.chassis_control_power_cycle()
                    except(pyipmi.errors.CompletionCodeError):
                        self.pr_msg(TmMsg.fail_restart(args.node, args.command))

                break
            except(RuntimeError):
                pass
        ipmi.session.close()
        if r:
            self.pr_msg(TmMsg.opaque('poweron' if r.__dict__['power_on']
                else 'poweroff'))

    def console(self, argv):
        parser = ArgumentParser(description="tm-console - access console.",
                    usage='tm console <node>')
        parser.add_argument('node', type=str, help=namehelp)
        args = parser.parse_args(argv[2:])

        if not self.owner_or_root(args.node, needuser=False):
            return
        addrs = self.get_addrs(args.node)
        if None in addrs:
            self.pr_msg(TmMsg.invalid_node(args.node))
            return

        r = self.db.get(Query().node == args.node)
        userpass = r['ipmipass'].split(',')
        cmd = 'ipmitool -I lanplus -H {} -U {} -P {} sol activate'.format(
                addrs[1], userpass[0], userpass[1])
        subprocess.call(split(cmd))
        print('\n')

    def log(self, output):
        self.output = output

    def owner_or_root(self, node, needuser=True):
        r = self.db.get(Query().node == node)
        if not r:
            self.pr_msg(TmMsg.invalid_node(node))
            return False
        elif 'user' not in r:
            if not needuser and self.user == 'root':
                return True
            elif needuser:
                self.pr_msg(TmMsg.not_reserved(node))
            elif self.user != 'root':
                self.pr_msg(TmMsg.need_owner_or_root(node))
            return False
        return True if self.user == r['user'] or self.user == 'root' else False

    def def_ipmi_addr(self, addr):
        iaddr = addr.split('.')
        iaddr[3] = str(int(iaddr[3])+self.ipmi_addr_off)
        return '.'.join(iaddr)

    def get_addrs(self, name):
        r = self.db.get(Query().node == name)
        return (r['ip'], self.def_ipmi_addr(r['ip'])) if r else (None, None)

    def is_mac(self, mac):
        l = mac.split(':')
        if len(l) != 6:
            return False
        for i in l:
            if len(i) != 2:
                return False
            if not match(r'[0-9a-f][0-9a-f]', i):
                return False
        return True

    def is_ipaddr(self, ip):
        l = ip.split('.')
        if len(l) != 4:
            return False
        for i in l:
            if not i.isdigit():
                return False
            elif int(i) > 255:
                return False
        return True

    def is_ipmipass(self, userpass):
        l = userpass.split(',')
        if len(l) != 2:
            return False
        elif len(l[0]) > 8 or len(l[1]) > 8:
            return False
        return True

    def set_loader(self, mac, d, node):
        dst = Path(self.tftpboot)/'pxelinux.cfg'/('01-'+mac.replace(':', '-'))
        # Unset existing one
        try:
            dst.unlink()
        except:
            print('{}: cannot remove the link {}'.format(node, dst))
        # set new one
        src = Path('../')/'loaders'/d/node
        try:
            dst.symlink_to(src)
            return True
        except:
            print('{}: failed to link to'.format(node, src))
            return False

    def reset_node(self, node, mac):
        if not self.set_loader(mac, 'base', node):
            self.pr_msg(TmMsg.restore_fail(node, mac))
        for e in ['user', 'expire']:
            self.db.update(delete(e), Query().node == node)

    def get_db(self, node=None):
        if node:
            res = [self.db.get(Query().node == node)]
            return None if res[0] is None else res
        res = self.db.all()
        return None if len(res) == 0 else res

    def pr_msg(self, msg):
        self.output = msg

if __name__ == '__main__':
    print(Tm(sys.argv).output)
