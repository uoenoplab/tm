#!/usr/bin/env python3
# -*- coding: utf-8 -*-:q

import argparse
import sys
import pyipmi
import pyipmi.interfaces
import socket

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

        add = subparsers.add_parser('add')
        lm = lambda o, t, r, h: add.add_argument(o, type=t, required=r, help=h)
        lm('--mac', str, True, 'MAC addr (e.g., 00:00:00:00:00:00)')
        lm('--ip', str, True, 'IPv4 addr (e.g., 192.168.0.2)')
        lm('--ipmi', str, True, 'IPMI user,pass (e.g., ADMIN,ADMIN)')
        lm('--cpu', str, True, 'CPU (e.g., Intel Xeon E3-1220v3)')
        lm('--ncpus', int, True, '# of CPU packages')
        lm('--ram', int, True, 'RAM in GB (e.g., 64)')
        lm('--nic', str, True, '(non-boot) NIC (e.g., Intel X520-SR2)')
        lm('--disk', str, False, 'Disk (e.g., Samsung Evo 870 256GB)')
        lm('--accel', str, False, 'Accelerator (e.g., ZOTAC GeForce GTX 1070)')
        lm('--note', str, False, 'Note (e.g., PCIe slot 1 is broken)')
        add.add_argument('node', type=str, help=namehelp)
        add.set_defaults(func='add')

        args = parser.parse_args(sys.argv[2:])
        if hasattr(args, 'node'):
            if args.node and None in self.addrs(args.node):
                print('{}: invalid node'.format(args.node))
                return
        print(args)

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
        if None in self.addrs(args.node):
            return

        print(args.node)

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
