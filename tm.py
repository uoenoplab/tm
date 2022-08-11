#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

# Copyright (C) 2020 Michio Honda.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
#Falsemodification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from argparse import ArgumentParser
import sys
import os
import pyipmi
import pyipmi.interfaces
import socket
import subprocess
from shlex import split
from tinydb import TinyDB, Query
from tinydb.operations import delete
from copy import copy
from tabulate import tabulate
from operator import itemgetter
from datetime import datetime, timedelta
import getpass
from pathlib import Path
from re import match, compile, search

DBFILE = '/usr/local/tm/tmdb.json'
TFTPBOOT = '/var/lib/tftpboot'
DHCPBOOT = str(Path(TFTPBOOT)/'machines')
FILESYSTEMS = '/opt/nfs/filesystems'
LINUX_BOOT = 'pxelinux.0'
GRUB_BOOT = 'grubnetaa64.efi.signed'
FREEBSD_BOOT = 'pxeboot'
PXEDIR = 'pxelinux.cfg'
GRUBDIR = 'grub'
namehelp = 'hostname (e.g., n04)'
dtfmt = '%d/%m/%y'
MAXDAYS = 7
KERNELVERSION = '5.8.0-25-generic'
FSVERSION = 'focal'

class TmMsg(object):
    def empty_db():
        return 'empty database'
    def not_in_inventory(node):
        return '{}: not in inventory'.format(node)
    def non_root(ops):
        return '{} command must be run by root'.format(ops)
    def invalid_node(node):
        return '{}: invalid node'.format(node)
    def in_use(node, user):
        return '{}: in use by {}'.format(node, user)
    def symlink_fail(node):
        return '{}: failed to create symlink'.format(node)
    def success(node, ops):
        return '{}: {} success'.format(node, ops)
    def fail(node, cmd):
        return '{}: failed in {}'.format(node, cmd)
    def df(d):
        return '{}'.format(d)

class Tm(object):
    def __init__(self, argv, dbfile=DBFILE, tftpboot=TFTPBOOT, pxedir=PXEDIR,
            dhcpboot=DHCPBOOT, linux_boot=LINUX_BOOT, freebsd_boot=FREEBSD_BOOT,
            filesystems=FILESYSTEMS, grubdir=GRUBDIR, grub_boot=GRUB_BOOT,
            test=False):
        self.output = ''
        self.tftpboot = tftpboot
        self.dhcpboot = dhcpboot
        self.pxedir = pxedir
        self.grubdir = grubdir
        self.filesystems = filesystems
        self.linux_boot = linux_boot
        self.freebsd_boot = freebsd_boot
        self.grub_boot = grub_boot
        self.db = TinyDB(dbfile)
        self.ipmi_addr_off = 100
        self.addrs = ('mac', 'ip', 'ipmiaddr', 'ipmipass')
        self.devices = ('disk', 'nic', 'accel')
        self.reservations = ('user', 'expire', 'email')
        self.curuser = getpass.getuser()
        self.test = test
        self.kernelversion = KERNELVERSION
        self.fsversion = FSVERSION
        self.sudo_user = None
        if 'SUDO_USER' in os.environ:
            self.sudo_user = os.environ['SUDO_USER']
        self.run = lambda cmd: subprocess.run(split(cmd),
                                              stdout=subprocess.DEVNULL)

        parser = ArgumentParser(description="tm - testbed management tool",
                usage='tm [-h] COMMAND <args>')
        parser.add_argument('command', metavar='COMMAND',
                choices=['inventory', 'power', 'console', 'reservation', 'user',
                    'filesystem'],
                help='{inventory|power|console|reservation|user|filesystem}')
        args = parser.parse_args(argv[1:2])
        getattr(self, args.command)(argv)

    def reservation(self, argv):
        parser = ArgumentParser(description="tm-reservation - node reservation",
                usage='tm reservation COMMAND [<args>]')
        subparsers = parser.add_subparsers(title='COMMAND')
        for cmd in ('reserve', 'update', 'release', 'show', 'clean'):
            p = subparsers.add_parser(cmd,
                    usage='tm reservation {}'.format(cmd))
            if cmd == 'show':
                p.add_argument('--node', type=str, help=namehelp)
                p.usage += ' {}'.format('[--node NODE]')
            elif cmd == 'clean':
                p.add_argument('--noexpire', action='store_true',
                        help='release nodes regardless of expiration')
                p.usage += ' {}'.format('[--noexpire]')
            else:
                p.add_argument('node', type=str, help=namehelp)
                p.usage += ' {}'.format('<node>')
            if cmd == 'reserve' or cmd == 'update':
                p.add_argument('expire', type=str, help='dd/mm/yy')
                p.usage += ' {}'.format('<expire>')
                if cmd == 'reserve':
                    p.add_argument('email', type=str, help='email address')
                    p.usage += ' {}'.format('<email>')
            p.usage += ' {}'.format('[-h|--help]')
            p.set_defaults(func=cmd)
        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'): # XXX
            parser.print_help()
            return

        if args.func == 'show':
            ans = self.get_db(node=args.node)
            if not ans:
                if args.node:
                    self.pr_msg(TmMsg.not_in_inventory(args.node))
                else:
                    self.pr_msg(TmMsg.empty_db())
                return
            dics = sorted(ans, key=itemgetter('node'))
            cls = ('node', 'user', 'expire', 'email')
            newdics = []
            for d in dics:
                    newdics.append({k: d[k] for k in cls if k in d})
            self.pr_msg(tabulate(newdics, headers='keys'))
            return
        elif args.func == 'clean':
            if self.curuser != 'root':
                self.pr_msg(TmMsg.non_root(args.func))
                return
            today = datetime.now().date()
            ans = self.get_db()
            for v in ans:
                if not 'user' in v:
                    continue
                if (args.noexpire or
                    today > datetime.strptime(v['expire'], dtfmt).date()):
                    if not self.test:
                        self.power(
                            split('tm power poweroff {}'.format(v['node'])))
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
            elif self.curuser == 'root':
                self.pr_msg('root cannot reserve nodes')
                return
        elif args.func == 'release' or args.func == 'update':
            if not self.owner_or_root(args.node):
                return

        if args.func == 'reserve' or args.func == 'update':
            try:
                dt = datetime.strptime(args.expire, dtfmt).date()
            except(ValueError):
                self.pr_msg('date format must be dd/mm/yy')
                return
            if args.func == 'reserve':
                rc = compile(
                        r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$")
                if not match(rc, args.email):
                    self.pr_msg('{}: invalid email address'.format(args.email))
                    return
            today = datetime.now().date()
            if dt < today:
                self.pr_msg('date must be on or later than today')
                return
            else:
                latest = (datetime.now() + timedelta(days=MAXDAYS)).date()
                if dt > latest:
                    dt = latest
                    self.pr_msg('set {} days of of the maximum duration'.format(MAXDAYS))

            d = {'user':getpass.getuser(), 'expire': dt.strftime(dtfmt)}
            if args.func == 'reserve':
                if not self.reset_boot(args.node, r['mac']):
                    self.pr_msg(TmMsg.symlink_fail(args.node))
                    return
                if not self.set_loader(r['mac'], self.curuser, args.node):
                    self.pr_msg(TmMsg.symlink_fail(args.node))
                    return
                d['email'] = args.email
            self.db.update(d, Query().node == args.node)
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
                p.add_argument('--reservations', action='store_true',
                        help='reservations') 
            p.set_defaults(func=cmd)
        delete = subparsers.add_parser('delete')
        delete.add_argument('node', type=str, help=namehelp)
        delete.set_defaults(func='delete')

        t = True
        f = False
        for cmd in ('add', 'update'):
            p = subparsers.add_parser(cmd,
                    usage='tm inventory {} [<args>] <node>'.format(cmd))
            lm = lambda o, t, r, h: p.add_argument(o, type=t, required=r, help=h)
            lm('--mac', str, t, 'MAC addr (e.g., 00:00:00:00:00:00)')
            lm('--ip', str, t, 'IPv4 addr (e.g., 192.168.0.2)')
            lm('--ipmipass', str, t, 'IPMI user,pass (e.g., ADMIN,ADMIN)')
            lm('--cpu', str, t, 'CPU (e.g., Xeon E3-1220v3)')
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
        if hasattr(args, 'node'):
            if args.node:
                ans = self.db.get(Query().node == args.node)
                if args.func == 'add':
                    if ans and 'node' in ans:
                        self.pr_msg('{}: already exist'.format(args.node))
                        return
                elif None in self.get_addrs_dict(ans):
                    self.pr_msg(TmMsg.invalid_node(args.node))
                    return

        if args.func == 'delete':
            if 'user' in ans:
                self.pr_msg(TmMsg.in_use(args.node, ans['user']))
                return
            self.db.remove(doc_ids=[ans.doc_id,])
            self.pr_msg(TmMsg.success(args.node, args.func))

        elif args.func == 'add' or args.func == 'update':

            if args.mac:
                if not self.is_mac(args.mac):
                    self.pr_msg('{}: invalid MAC address'.format(args.node))
                    return
            if args.ip:
                if not self.is_ipaddr(args.ip):
                    self.pr_msg('{}: invalid IP address'.format(args.node))
                    return
            if args.ipmiaddr:
                if not self.is_ipaddr(args.ipmiaddr):
                    self.pr_msg('{}: invalid IPMI address'.format(args.node))
                    return
            if args.ipmipass:
                if not self.is_ipmipass(args.ipmipass):
                    self.pr_msg('{}: IPMI login must be USER,PASS'.format(
                        args.node))
                    return

            d = {k:v for k, v in vars(args).items() if v is not None}
            del d['func']
            if args.func == 'update':
                del d['node']
                for k, v in d.items():
                    if search(',', v):
                        d[k] = v.replace(',', '\n')
                self.db.update(d, Query().node == args.node)
            else:
                self.db.insert(d)
            self.pr_msg(TmMsg.success(args.node, args.func))

        elif args.func == 'show' or args.func == 'test':
            ans = self.get_db(node=args.node)
            if ans is None:
                if args.node:
                    self.pr_msg(TmMsg.not_in_inventory(args.node))
                else:
                    self.pr_msg(TmMsg.empty_db())
            elif args.func == 'show':
                dics = sorted(ans, key=itemgetter('node'))
                cls = list(dics[0].keys())
                reorders = ['node', 'mac', 'ip', 'ipmiaddr']
                for i, r in enumerate(reorders):
                    cls.remove(r)
                    cls.insert(i, r)
                for a in ('addrs', 'devices', 'reservations'):
                    if not getattr(args, a):
                        cls = [c for c in cls if c not in getattr(self, a)]
                newdics = []
                for d in dics:
                    newdics.append({k: d[k] for k in cls if k in d})
                self.pr_msg(tabulate(newdics, headers='keys'))
            else:
                for node in ans:
                    # test dns
                    try:
                        addr = socket.gethostbyname(node['node'])
                    except(socket.gaierror):
                        self.pr_msg('{}: no network name'.format(node['node']))
                        return

                    # compare with those registered to inventory
                    msg = (node['node'] +
                            ': Network address {} {} inventory one {}')
                    m = 'unmatches' if addr != node['ip'] else 'matches'
                    print(msg.format(addr, m, node['ip']))

                    if self.def_ipmi_addr(addr) != node['ipmiaddr']:
                        self.pr_msg('{}: ipmi addr {} differs from the default one {}'.format(
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
                    loaderpath = Path(self.dhcpboot)/self.pxedir
                    cmd = 'ls {}'.format(loaderpath)
                    msg = node['node'] + ': loader {} {} in ' + str(loaderpath)
                    try:
                        res = subprocess.check_output(split(cmd))
                    except(subprocess.CalledProcessError) as e:
                        self.pr_msg(TmMsg.fail(node['node'], cmd))
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
                        self.pr_msg(TmMsg.fail(node['node'], cmd))
                    for line in res.split('\n'):
                        mac, ip, name = line.split(',')
                        if node['node'] == name:
                            if node['mac'] == mac and node['ip'] == ip:
                                print('{}: MAC and IP address found in '
                                      '/etc/dnsmasq.conf'.format(node['node']))
                                break
                            m = '{}: inventory {} registered {}'
                            if node['mac'] != mac:
                                print(m.format(name, node['mac'], mac))
                            if node['ip'] != ip:
                                print(m.format(name, node['ip'], ip))
                            break
                    else:
                        self.pr_msg('{}: not in /etc/dnsmasq.conf'.format(node['node']))

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
        userpass = self.get_ipmi_cred(args.node)
        ipmi.session.set_auth_type_user(userpass[0], userpass[1])
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
                    self.pr_msg('{}: cannot restart, power might be off'.format(
                        args.node))
        except(RuntimeError):
            pass
        ipmi.session.close()
        if r:
            self.pr_msg('poweron' if r.__dict__['power_on'] else 'poweroff')

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

        userpass = self.get_ipmi_cred(args.node)
        cmd = 'ipmitool -I lanplus -H {} -U {} -P {} sol activate'.format(
                addrs[1], userpass[0], userpass[1])
        subprocess.call(split(cmd))
        print('\n')

    def user(self, argv):
        parser = ArgumentParser(description="tm-user - user management",
                    usage='tm user COMMAND <user>')
        parser.add_argument('command', metavar='COMMAND', type=str,
                            choices=['add', 'delete'], help='{add|delete}')
        parser.add_argument('user', type=str, help='user name')
        args = parser.parse_args(argv[2:])
        user = args.user

        if not self.curuser == 'root':
            self.pr_msg(TmMsg.non_root('user'))
            return

        r = self.run('getent passwd {}'.format(user))
        if r.returncode != 0:
            self.pr_msg('no user')
            return

        dirs = ('loaders', 'kernels', 'initrd-imgs', 'filesystems')

        if args.command == 'delete':
            # ensure no reservation
            ans = self.get_db_from_user(user)
            if ans:
                self.pr_msg('{} still reserves {}'.format(user,
                    ', '.join([d['node'] for d in ans])))
                return
            # ensure current proper existence
            for p in dirs:
                d = Path(self.tftpboot)/p/user
                if not d.exists():
                    self.pr_msg('{} is missing'.format(d))
                    return
            cmdstr = 'rm -rf'
            for p in dirs:
                cmdstr += ' ' + str(Path(self.tftpboot)/p/user)
            self.pr_msg('run: sudo {}'.format(cmdstr))
            return

        for p in dirs:
            d = Path(self.tftpboot)/p/user
            if d.exists():
                self.pr_msg('{} exists'.format(d))
                return

        # create homes
        for p in dirs:
            c = 'mkdir -m 755 {}'.format(Path(self.tftpboot)/p/user)
            r = self.run(c)
            if r.returncode != 0:
                self.pr_msg('error in {}'.format(c))
                return

        # copy loaders
        p = Path(self.tftpboot)/'loaders'
        c = 'cp {} {}'.format(p/'base'/'*', p/user)
        r = subprocess.run(c, shell=True)
        if r.returncode != 0:
            self.pr_msg('error in {}'.format(c))
            return

        # replace initrd-imgs, kernels and filesystem the loaders point to
        c1 = 'for l in `ls {}` ; do sed -i "s/base/{}/g" {}/$l; done'.format(
            p/user, user, p/user)
        c2 = 'for l in `ls {}` ; do sed -i "s/ ro / rw /g" {}/$l; done'.format(
            p/user, p/user)
        for c in (c1, c2):
            r = subprocess.run(c, shell=True)
            if r.returncode != 0:
                self.pr_msg('error in {}'.format(cmd))
                return

        # copy the base initrd-img, kernel and file system
        for o in (('initrd-imgs', 'initrd.img'), ('kernels', 'vmlinuz')):
            p = Path(self.tftpboot)/o[0]
            c = 'cp {} {}'.format(p/'base'/'{}-{}'.format(o[1],
                self.kernelversion), p/user)
            r = self.run(c)
            if r.returncode != 0:
                self.pr_msg('error in {}'.format(c))
                return

        # fix permission
        for d in dirs:
            p = Path(self.tftpboot)/d
            cmd = 'chown'
            if d != 'filesystems':
                cmd += ' -R'
            self.run(cmd + ' {}:{} {}'.format(user, user, p/user))

        # create the file system
        self.newfilesystem(user)
        self.pr_msg(TmMsg.success('user', 'add'))

    # sudo from any user
    # %bar    ALL=(ALL) NOPASSWD: tm filesystem *
    def filesystem(self, argv):
        u = self.curuser
        if self.sudo_user:
            u = self.sudo_user
        parser = ArgumentParser(
                description="tm-filesystem - filesystem operation",
                usage='sudo tm filesystem COMMAND [<args>]')
        subparsers = parser.add_subparsers(title='COMMAND')
        for cmd in ('clone', 'new', 'delete'):
            p = subparsers.add_parser(cmd,
                    usage='tm filesystem {}'.format(cmd))
            if cmd == 'clone' or cmd == 'delete':
                p.add_argument('src', type=str,
                        help='filesystem name in {}/{}'.format(
                            self.filesystems, u))
            if cmd == 'clone':
                p.add_argument('dst', type=str, help='new filesystem name')
                p.usage += ' {}'.format('<new filesystem>')
            p.usage += ' {}'.format('[-h|--help]')
            p.set_defaults(func=cmd)
        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'): # XXX
            parser.print_help()
            return
        if 'src' in args:
            if search('/', args.src):
                self.pr_msg('provide a filesystem name only (no full path)')
                return
        if 'dst' in args:
            if search('/', args.dst):
                self.pr_msg('provide a filesystem name only (no full path)')
                return

        if self.sudo_user is None:
            self.pr_msg(TmMsg.non_root(args.func))
            return
        u = self.sudo_user
        path = Path(self.filesystems)
        if args.func == 'new':
            d = path/u/self.fsversion
            if d.exists():
                self.pr_msg('{} exists'.format(d))
            else:
                self.newfilesystem(u)
            return
        elif args.func == 'clone':
            d = path/u/args.dst
            if d.exists():
                self.pr_msg('{} exists'.format(d))
                return
            cmd = 'cp -Rp {} {}'.format(path/u/args.src, path/u/args.dst)
        elif args.func == 'delete':
            d = path/u/args.src
            if not d.exists():
                self.pr_msg('{} does not exist'.format(d))
                return
            cmd = 'rm -rf {}'.format(path/u/args.src)
        print(cmd)
        self.run(cmd)
        if args.func == 'clone':
            cmd = 'chown {}:{} {}'.format(
                    self.sudo_user, self.sudo_user, path/u/args.dst)
            print(cmd)
            self.run(cmd)

    def owner_or_root(self, node, needuser=True):
        r = self.db.get(Query().node == node)
        if not r:
            self.pr_msg(TmMsg.invalid_node(node))
            return False
        elif 'user' not in r:
            if not needuser and self.curuser == 'root':
                return True
            elif needuser:
                self.pr_msg('{}: not reserved'.format(node))
            elif self.curuser != 'root':
                self.pr_msg('{}: need reservation or to be root'.format(node))
            return False
        return True if self.curuser == r['user'] or self.curuser == 'root' else False

    def def_ipmi_addr(self, addr):
        iaddr = addr.split('.')
        iaddr[3] = str(int(iaddr[3])+self.ipmi_addr_off)
        return '.'.join(iaddr)

    def get_addrs_dict(self, d):
        return (d['ip'], self.def_ipmi_addr(d['ip'])) if d else (None, None)

    def get_addrs(self, name):
        r = self.db.get(Query().node == name)
        return self.get_addrs_dict(r)

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

    def set_loader(self, mac, u, node):
        # Try pxelinux first
        d = Path(self.dhcpboot)/Path(self.pxedir)/( '01-'+mac.replace(':', '-'))
        # d.exists() doesn't work for broken symlink (missing user config file)
        try:
            d.lstat()
        except:
            d = Path(self.tftpboot)/Path(self.grubdir)/(mac)
        s = Path('../')/'loaders'/u/node
        return self.set_link(s, d)

    def set_link(self, src, dst):
        try:
            dst.unlink()
        except:
            print('cannot remove the link {}'.format(dst))
        try:
            dst.symlink_to(src)
            return True
        except:
            print('failed to link to'.format(src))
            return False

    def reset_boot(self, node, mac):
        d = Path(self.dhcpboot)/Path(self.pxedir)/( '01-'+mac.replace(':', '-'))
        try:
            d.lstat()
        except:
            return self.set_link(self.grub_boot, Path(self.dhcpboot)/node)
        return self.set_link(self.linux_boot, Path(self.dhcpboot)/node)

    def reset_node(self, node, mac):
        # reset to Linux
        self.reset_boot(node, mac)
        if not self.set_loader(mac, 'base', node):
            self.pr_msg('{}: cannot restore symlink for {}'.format(node, mac))
        for e in ['user', 'expire', 'email']:
            self.db.update(delete(e), Query().node == node)

    def newfilesystem(self, user):
        path = Path(self.filesystems)
        cmd = 'tar xzpf {}.tar.gz -C {}'.format(
                path/"base"/self.fsversion, path/user)
        print(cmd)
        self.run(cmd)
        self.run('chown {}:{} {}'.format(user, user,
            path/user/self.fsversion))

    def get_db_from_user(self, user):
        res = [self.db.get(Query().user == user)]
        return None if res[0] is None else res

    def get_db(self, node=None):
        if node:
            res = [self.db.get(Query().node == node)]
            return None if res[0] is None else res
        res = self.db.all()
        return None if len(res) == 0 else res

    def get_ipmi_cred(self, node):
        r = self.db.get(Query().node == node)
        return r['ipmipass'].split(',')

    def pr_msg(self, msg):
        self.output = msg

if __name__ == '__main__':
    print(Tm(sys.argv).output)

