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

DBFILE = '/usr/local/tm/tmdb.json'
TFTPBOOT = '/var/lib/tftpboot'
namehelp = 'hostname (e.g., n04)'
dtfmt = '%d/%m/%y'
MAXDAYS = 14


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
        self.init_msgs()

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
                self.pr_msg('empty_db', args.node)
                return
            df = DataFrame.from_dict(ans)
            self.pr_msg('df', None,
                    df.reindex(columns=('node', 'user', 'expire')))
            return

        if args.func == 'clean':
            if self.user != 'root':
                self.pr_msg('clean_must_be_root', None)
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
            self.pr_msg('invalid_node', args.node)
            #self.log('{}: invalid node'.format(args.node))
            return
        elif args.func == 'reserve':
            if 'user' in r:
                self.pr_msg('node_in_use2', args.node, r['user'])
                return
            elif self.user == 'root':
                self.pr_msg('reserve_by_root', args.node)
                return
        elif args.func == 'release' or args.func == 'update':
            if not self.owner_or_root(args.node):
                return
        elif args.func == 'clean':
            if self.user != 'root':
                self.pr_msg('clean_must_be_root', None)

        if args.func == 'reserve' or args.func == 'update':
            try:
                dt = datetime.strptime(args.expire, dtfmt).date()
            except(ValueError):
                self.log('expiration date format must be dd/mm/yy'
                         ', not {}'.format(args.expire))
                return
            today = datetime.now().date()
            if dt < today:
                self.log('date must be on or later than today')
                return
            else:
                latest = (datetime.now() + timedelta(days=MAXDAYS)).date()
                if dt > latest:
                    dt = latest
                    print('14 days of the maximum reservation is set')

            if args.func == 'reserve':
                if not self.set_loader(r['mac'], self.user, args.node):
                    self.log('{}: failed to create symlink'.format(args.node))
                    return

            self.db.update({'user': getpass.getuser(),
                'expire': dt.strftime(dtfmt)}, Query().node == args.node)
        else:
            if not self.test:
                self.power(split('tm power poweroff {}'.format(args.node)))
            self.reset_node(args.node, r['mac'])
        self.log('{}: {} successful'.format(args.node, args.func))

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
                self.log('{}: invalid node'.format(args.node))
                return

        if args.func == 'add' or args.func == 'update':
            d = copy(vars(args))
            del d['func']
            if args.func == 'update':
                del d['node']
                self.db.update(d, Query().node == args.node)
            else:
                self.db.insert(d)
            self.log('success')

        elif args.func == 'show' or args.func == 'test':
            ans = self.get_db(node=args.node)
            if ans is None:
                self.log('no db entry')
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
                self.log(df.reindex(columns=cls))
            else:
                for node in ans:
                    # test dns
                    try:
                        addr = socket.gethostbyname(node['node'])
                    except(socket.gaierror):
                        self.log('{}: Cannot resolve name. Check /etc/hosts and '
                              '/etc/dnsmasq.conf'.format(node['node']))
                        return

                    # compare with those registered to inventory
                    msg = (node['node'] +
                            ': Network address {} {} inventory one {}')
                    m = 'unmatches' if addr != node['ip'] else 'matches'
                    print(msg.format(addr, m, node['ip']))

                    if self.def_ipmi_addr(addr) != node['ipmiaddr']:
                        self.log('Warning: ipmiaddr {} differs from the '
                              'default'.format(self.def_ipmi_addr(addr)))

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
                        self.log('{}: {} failed {}'.format(node['node'], cmd, e))
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
                        print('{}: failed in {}'.format(node['node'], cmd))
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
                        print('{}: not in /etc/dnsmasq.conf'.format(
                            node['node']))
                        return

        elif args.func == 'delete':
            r = self.db.get(Query().node == args.node)
            if r:
                self.db.remove(doc_ids=[r.doc_id,])
            else:
                self.log('{} does not exist in the db'.format(args.node))

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
            self.log('{} does not exist'.format(args.node))
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
                        self.log('{}: failed to {}, '
                              'perhaps the power is off?'.format(
                              args.node, args.command))

                break
            except(RuntimeError):
                pass
        ipmi.session.close()
        if r:
            self.log('{}'.format('poweron' if r.__dict__['power_on']
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
            self.log('{}: invalid node'.format(args.node))
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
            self.pr_msg('not_in_inventory', node)
            return False
        elif 'user' not in r:
            if not needuser and self.user == 'root':
                return True
            elif needuser:
                self.log('{}: node is not reserved'.format(node))
            elif self.user != 'root':
                self.log('{}: need reservation or to be root'.format(node))
            return False
        return True if self.user == r['user'] or self.user == 'root' else False

    def def_ipmi_addr(self, addr):
        iaddr = addr.split('.')
        iaddr[3] = str(int(iaddr[3])+self.ipmi_addr_off)
        return '.'.join(iaddr)

    def get_addrs(self, name):
        r = self.db.get(Query().node == name)
        return (r['ip'], self.def_ipmi_addr(r['ip'])) if r else (None, None)

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
            self.log('{}: cannot restore symlink for {}'.format(node, mac))
        for e in ['user', 'expire']:
            self.db.update(delete(e), Query().node == node)

    def get_db(self, node=None):
        if node:
            res = [self.db.get(Query().node == node)]
            return None if res[0] is None else res
        res = self.db.all()
        return None if len(res) == 0 else res

    def init_msgs(self):
        self.msgs = {
            'empty_db': 'empty database',
            'not_in_inventory': 'not in inventory',
            'clean_must_be_root': 'clean command must be run by root',
            'invalid_node': 'invalid node',
            'node_in_use2': ' node in use by {}',
            'reserve_by_root': 'root user cannot reserve nodes',
            'invalid_date_format': 'date format must be dd/mm/yy',
            'invalid_date': 'date must be on or later than today',
            'shrinked_date': '7 days of the maximum reservation has been set',
            'symlink_fail': 'failed to create symlink',
            'success2': '{} successful',
            'no_host': 'no network name - check hosts and dnsmasq.conf',
            'non_def_ipmi': 'ipmi addr {} differs from the defaule one',
            'reachable': 'reachable',
            'unreachable': 'unreachable',
            'no_dnsmasq_conf': 'not in /etc/dnsmasq.conf',
            'fail2': 'failed in {}',
            'fail3': '{} failed in {}',
            'no_db': 'is not in the db',
            'power': '{}',
            'fail_restart': 'failed to restart, perhaps the power is off',
            'df': '{}',
        }

    def pr_msg(self, type, node, *args):
        m = ''
        if node:
            m = '{}: '.format(node)
        m += self.msgs[type].format(*args)
        print(m)

if __name__ == '__main__':
    print(Tm(sys.argv).output)
