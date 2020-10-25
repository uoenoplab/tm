#!/usr/bin/env python3
# -*- coding: utf-8 -*-:q

import argparse
import sys

namehelp = 'Hostname (e.g., 04)'

class Tm(object):
    def __init__(self):
        parser = argparse.ArgumentParser(
                description="tm - testbed management tool",
                usage='tm [-h] COMMAND <args>')
        parser.add_argument('command', metavar='COMMAND', help='{inventory|power|console}')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognized command', args.command)
            parser.print_help()
        else:
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
        add.add_argument('--mac', type=str, required=True,
                help='MAC addr (e.g, 00:00:00:00:00:00)')
        add.add_argument('--ip', type=str, required=True,
                help='IPv4 addr (e.g., 192.168.0.2)')
        add.add_argument('--nic', type=str, required=True,
                help='NIC model (e.g., Intel X520-SR2)')
        add.add_argument('--cpu', type=str, required=True,
                help='CPU model (e.g., Intel Xeon E3-1220v3)')
        add.add_argument('--ncpus', type=int, required=True,
                help='# of CPU packages')
        add.add_argument('--ram', type=int, required=True,
                help='RAM in GB (e.g., 64)')
        add.add_argument('--disk', type=str, required=True,
                help='Disk model (e.g., Samsung Evo 870 256GB)')
        add.add_argument('--gpu', type=str, required=True,
                help='GPU model (e.g., ZOTAC GeForce GTX 1070)')
        add.add_argument('--note', type=str,
                help='Note (e.g., PCIe slot 1 is broken)')
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
