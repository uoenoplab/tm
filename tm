#!/usr/bin/env python3
# -*- coding: utf-8 -*-:q

import argparse
import sys

namehelp = 'Hostname (e.g., n04)'

class Tm(object):
    def __init__(self):
        parser = argparse.ArgumentParser(
                description="tm - testbed management tool",
                usage='tm [-h] COMMAND <args>')
        parser.add_argument('command', metavar='COMMAND',
                help='{inventory|power|console}')
        args = parser.parse_args(sys.argv[1:2])
        if hasattr(self, args.command):
            getattr(self, args.command)()
        else:
            print('Unrecognized command', args.command)
            parser.print_help()

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
        lm('--nic', str, True, '(non-boot) NIC model (e.g., Intel X520-SR2)')
        lm('--cpu', str, True, 'CPU model (e.g., Intel Xeon E3-1220v3)')
        lm('--ncpus', int, True, '# of CPU packages')
        lm('--ram', int, True, 'RAM in GB (e.g., 64)')
        lm('--disk', str, True, 'Disk model (e.g., Samsung Evo 870 256GB)')
        lm('--gpu', str, True, 'GPU model (e.g., ZOTAC GeForce GTX 1070)')
        lm('--note', str, False, 'Note (e.g., PCIe slot 1 is broken)')
        add.add_argument('node', type=str, help=namehelp)
        add.set_defaults(func='add')

        args = parser.parse_args(sys.argv[2:])
        print(args)

    def power(self):
        parser = argparse.ArgumentParser(
                description="tm-power - power management")
        parser.add_argument('command', metavar='command', type=str,
                help='{status|poweron|poweroff|restart}')
        parser.add_argument('node', type=str, help=namehelp)
        args = parser.parse_args(sys.argv[2:])
        print(args.command)

    def console(self):
        parser = argparse.ArgumentParser(
                description="tm-console - console connection.")
        parser.add_argument('node', type=str,
                help=namehelp)
        args = parser.parse_args(sys.argv[2:])
        print(args.node)

if __name__ == '__main__':
    Tm()
