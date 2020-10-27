#!/usr/bin/env python3
# -*- coding: utf-8 -*-:q

import argparse
import sys
import pyipmi
import pyipmi.interfaces
import socket
import subprocess
import shlex
from tinydb import TinyDB, Query
import copy
import pandas as pd

"""
./tm inventory add --mac 20:47:47:88:cd:9c --ip=192.168.56.12 --ipmipass
root,calvin --cpu "Xeon Haswell" --ncpus 2 --ram 32 --nic "XXV710-DA2" n02
./tm inventory add --mac 90:e2:ba:48:46:60 --ip=192.168.56.11 --ipmipass
ADMIN,ADMIN --cpu "Xeon Silver" --ncpus 2 --ram 64 --nic "XXV710-DA2" n01
"""


DBFILE = 'tmdb.json'
namehelp = 'Hostname (e.g., n04)'

class Tm(object):
    def __init__(self):
        self.loaderpath = '/var/lib/tftpboot/pxelinux.cfg'
        self.ipmi_addr_off = 100
        self.db = TinyDB(DBFILE)

        parser = argparse.ArgumentParser(
                description="tm - testbed management tool",
                usage='tm [-h] COMMAND <args>')
        parser.add_argument('command', metavar='COMMAND',
                choices=['inventory', 'power', 'console'],
                help='{inventory|power|console}')
        args = parser.parse_args(sys.argv[1:2])
        getattr(self, args.command)()

    def inventory(self):
        parser = argparse.ArgumentParser(
                description="tm-inventory - node metadata management")
        subparsers = parser.add_subparsers(title='COMMAND')

        for cmd in ('show', 'test'):
            p = subparsers.add_parser(cmd)
            p.add_argument('--node', type=str, help=namehelp)
            p.set_defaults(func=cmd)

        delete = subparsers.add_parser('delete')
        delete.add_argument('node', type=str, help=namehelp)
        delete.set_defaults(func='delete')

        for cmd in ('add', 'update'):
            p = subparsers.add_parser(cmd)
            lm = lambda o, t, r, h: p.add_argument(o, type=t, required=r, help=h)
            lm('--mac', str, True, 'MAC addr (e.g., 00:00:00:00:00:00)')
            lm('--ip', str, True, 'IPv4 addr (e.g., 192.168.0.2)')
            lm('--ipmipass', str, True, 'IPMI user,pass (e.g., ADMIN,ADMIN)')
            lm('--cpu', str, True, 'CPU (e.g., Intel Xeon E3-1220v3)')
            lm('--ncpus', int, True, '# of CPU packages')
            lm('--ram', int, True, 'RAM in GB (e.g., 64)')
            lm('--nic', str, True, '(non-boot) NIC (e.g., Intel X520-SR2)')
            lm('--disk', str, False, 'Disk (e.g., Samsung Evo 870 256GB)')
            lm('--accel', str, False, 'Accelerator (e.g., ZOTAC GeForce GTX 1070)')
            lm('--note', str, False, 'Note (e.g., PCIe slot 1 is broken)')
            lm('--ipmiaddr', str, False, 'IPMI address (e.g., if not ip+100)')
            p.add_argument('node', type=str, help=namehelp)
            p.set_defaults(func=cmd)

        args = parser.parse_args(sys.argv[2:])
        if args.func != 'add' and hasattr(args, 'node'):
            if args.node and None in self.addrs(args.node):
                print('{}: invalid node'.format(args.node))
                return

        #add example --mac=00:00:00:00:00:00 --ip=192.168.56.11 --ipmi=ADMIN,ADMIN --cpu=Xeon --ncpus=1 --ram=32 --nic=x520-SR2 n01
        if args.func == 'add':
            d = copy.copy(vars(args))
            del d['func']
            self.db.insert(d)
            print(d)

        elif args.func == 'show' or args.func == 'test':
            if args.node:
                res = [self.db.get(Query().node == args.node)]
            else:
                res = self.db.all()
                if len(res) == 0:
                    print('empty inventory')
                    return

            if args.func == 'show':
                df = pd.DataFrame.from_dict(res)
                columns = list(df.columns)
                columns.remove('node')
                columns.insert(0, 'node')
                print(df.reindex(columns=columns))

            else:
                for node in res:
                    # test dns
                    try:
                        addr = socket.gethostbyname(node['node'])
                    except(socket.gaierror):
                        print('{}: Cannot resolve name. Check /etc/hosts and '
                              '/etc/dnsmasq.conf'.format(node['node']))
                        return

                    # compare with those registered to inventory
                    msg = (node['node'] +
                            ': Network address {} {} inventory one {}')
                    m = 'unmatches' if addr != node['ip'] else 'matches'
                    print(msg.format(addr, m, node['ip']))

                    if self.default_ipmi_addr(addr) != node['ipmiaddr']:
                        print('Warning: ipmiaddr {} differs from the '
                              'default'.format(self.default_ipmi_addr(addr)))

                    # test ipmi
                    cmd = 'ping -c 2 {}'.format(node['ipmiaddr'])
                    msg = node['node'] + ': IPMI {} {}'
                    try:
                        subprocess.call(shlex.split(cmd),
                                stdout=subprocess.DEVNULL)
                        print(msg.format(node['ipmiaddr'], 'reachable'))
                    except(OSError) as e:
                        print(msg.format(node['ipmiaddr'], 'unreachable'))

                    # test loader
                    cmd = 'ls {}'.format(self.loaderpath)
                    msg = node['node'] + ': loader {} {} in ' + self.loaderpath
                    try:
                        res = subprocess.check_output(shlex.split(cmd))
                    except(subprocess.CalledProcessError) as e:
                        print('{}: {} failed {}'.format(node['node'], cmd, e))
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
                print('{} does not exist in the db'.format(args.node))

    def power(self):
        parser = argparse.ArgumentParser(
                description="tm-power - power management")
        parser.add_argument('command', metavar='command', type=str,
        choices=['status', 'poweron', 'poweroff', 'restart'],
                help='{status|poweron|poweroff|restart}')
        parser.add_argument('node', type=str, help=namehelp)

        args = parser.parse_args(sys.argv[2:])
        addr = self.addrs(args.node)[1]
        if not addr:
            print('{} does not exist'.format(args.node))
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
                    r = ipmi.chassis_control_power_cycle()
                break
            except(RuntimeError):
                pass
        ipmi.session.close()
        if r:
            print('{}', r.__dict__)

    def console(self):
        parser = argparse.ArgumentParser(
                description="tm-console - console connection.")
        parser.add_argument('node', type=str,
                help=namehelp)
        args = parser.parse_args(sys.argv[2:])
        addrs = self.addrs(args.node)
        if None in addrs:
            return

        userpass = ('root', 'calvin')
        cmd = 'ipmitool -I lanplus -H {} -U {} -P {} sol activate'.format(
                addrs[1], userpass[0], userpass[1])
        subprocess.call(shlex.split(cmd))
        print('\n')

    def default_ipmi_addr(self, addr):
        iaddr = addr.split('.')
        iaddr[3] = str(int(iaddr[3])+self.ipmi_addr_off)
        return '.'.join(iaddr)

    def addrs(self, name):
        try:
            r = self.db.get(Query().node == name)
            addr = r['ip']
        except(socket.gaierror):
            return (None, None)
        return (addr, self.default_ipmi_addr(addr))

if __name__ == '__main__':
    Tm()
