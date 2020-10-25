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

namehelp = 'Hostname (e.g., n04)'

class Tm(object):
    def __init__(self):
        self.ipmi_addr_off = 100

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
        show = subparsers.add_parser('show')
        show.add_argument('--node', type=str, help=namehelp)
        show.set_defaults(func='show')

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
        if hasattr(args, 'node'):
            if args.node and None in self.addrs(args.node):
                print('{}: invalid node'.format(args.node))
                return

        #add example --mac=00:00:00:00:00:00 --ip=192.168.56.11 --ipmi=ADMIN,ADMIN --cpu=Xeon --ncpus=1 --ram=32 --nic=x520-SR2 n01
        db = TinyDB('tmdb.json')
        if args.func == 'add':
            d = copy.copy(vars(args))
            del d['func']
            db.insert(d)
            print(d)
        elif args.func == 'show':
            if args.node:
                r = db.search(Query().node == args.node)
            else:
                table = db.table(db.tables().pop())
                r = table.all()
            df = pd.DataFrame.from_dict(r)
            columns = list(df.columns)
            columns.remove('node')
            columns.insert(0, 'node')
            print(df.reindex(columns=columns))

        elif args.func == 'delete':
            r = db.get(Query().node == args.node)
            if r:
                db.remove(doc_ids=[r.doc_id,])
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

    def addrs(self, name):
        try:
            addr = socket.gethostbyname(name)
        except(socket.gaierror):
            return (None, None)
        iaddr = addr.split('.')
        iaddr[3] = str(int(iaddr[3])+self.ipmi_addr_off)
        return (addr, '.'.join(iaddr))

if __name__ == '__main__':
    Tm()
