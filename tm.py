#!/usr/bin/env python3
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
import platform
import socket
import paramiko
import json
import subprocess
import shlex
from shlex import split
from tinydb import TinyDB, Query, where
from tinydb.operations import delete
from tabulate import tabulate
from operator import itemgetter
from datetime import datetime, timedelta
import getpass
from pathlib import Path
import re
from re import search, sub
from ipaddress import IPv4Address

DBFILE = '/usr/local/tm/tmdb.json'
TFTPBOOT = '/var/lib/tftpboot'
DHCPBOOT = str(Path(TFTPBOOT)/'machines')
FILESYSTEMS = '/opt/nfs/filesystems'
GRUB_LINUX_AA64 = 'grubnetaa64.efi.signed'
GRUB_LINUX_X64 = 'grubnetx64.efi.signed'
GRUBDIR = 'grub'
namehelp = 'hostname (e.g., n04)'
dtfmt = '%d/%m/%y'
MAXDAYS = 7
KERNELVERSION = '6.8.0-49-generic'
FSVERSION = 'noble'
NETWORKNODE = ['s01', 's03']

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
    def success(node, ops):
        return '{}: {} success'.format(node, ops)
    def fail(node, cmd):
        return '{}: failed in {}'.format(node, cmd)
    def df(d):
        return '{}'.format(d)

class Tm(object):
    def __init__(self, argv, dbfile=DBFILE, tftpboot=TFTPBOOT,
            dhcpboot=DHCPBOOT, filesystems=FILESYSTEMS, grubdir=GRUBDIR,
            test=False):
        self.os = platform.system()
        self.output = ''
        self.tftpboot = tftpboot
        self.dhcpboot = dhcpboot
        self.grubpath = Path(self.tftpboot)/grubdir
        self.filesystems = filesystems
        self.db = TinyDB(dbfile)
        self.ipmi_addr_off = 100
        self.addrs = ('mac', 'ip', 'ipmiaddr', 'ipmipass')
        self.devices = ('disk', 'nic', 'ram', 'owner', 'note', 'boot')
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
                    'filesystem', 'network'],
                help='{inventory|power|console|reservation|user|filesystem}')
        args = parser.parse_args(argv[1:2])
        getattr(self, args.command)(argv)

    def reservation(self, argv):
        parser = ArgumentParser(description="tm-reservation - node reservation",
                usage='tm reservation COMMAND [<args>]')
        subparsers = parser.add_subparsers(title='COMMAND')
        for cmd in ('reserve', 'update', 'release', 'show', 'clean', 'history'):
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
            elif cmd == 'history':
                p.add_argument('--trim', type=str,
                        help='number of days to keep the history')
                p.usage += ' {}'.format('[--trim]')
            p.usage += ' {}'.format('[-h|--help]')
            p.set_defaults(func=cmd)
        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'): # XXX
            parser.print_help()
            return

        now = datetime.now()

        if args.func == 'show':
            ans = self.get_db(node=args.node)
            if not ans:
                self.pr_msg(TmMsg.not_in_inventory(args.node)
                        if args.node else TmMsg.empty_db())
                return
            dics = sorted(ans, key=itemgetter('node'))
            # Add extra info
            for d in dics:
                if 'user' in d:
                    d['email'] = self.get_email(d['user'])

            cls = ('node', 'user', 'expire', 'email')
            newdics = [{k: d[k] for k in cls if k in d} for d in dics]
            self.pr_msg(tabulate(newdics, headers='keys'))
            return

        elif args.func == 'clean':
            if self.curuser != 'root':
                self.pr_msg(TmMsg.non_root(args.func))
                return
            ans = self.get_db()
            for v in ans:
                if not 'user' in v:
                    continue
                if (args.noexpire or now.date()
                        >= datetime.strptime(v['expire'], dtfmt).date()):
                    self.do_release(v, now)
            return

        r = self.db.get(Query().node == args.node)
        if not r:
            self.pr_msg(TmMsg.invalid_node(args.node))
            return

        if args.func == 'history':
            if 'history' not in r:
                self.pr_msg('no history in {}'.format(args.node))
                return
            h = r['history']
            if args.trim:
                if not args.trim.isdigit():
                    self.pr_msg('{}: invalid number of dates'.format(args.trim))
                    return
                for cnt, i in enumerate(reversed(h)):
                    end = datetime.fromisoformat(i[2]) if i[2] else now
                    end = end.date()
                    if end <= now.date() - timedelta(days=int(args.trim)):
                        break
                else:
                    return
                self.db.update(delete('history') if cnt == 0 else {'history':
                    h[-cnt:]}, Query().node == args.node)
                return
            t = []
            for i in h:
                start = datetime.fromisoformat(i[1])
                delta = (datetime.fromisoformat(i[2]) if i[2] else now) - start
                t.append( (i[0], datetime.strftime(start, '%b %d %H:%M:%S %Y'),
                    delta - timedelta(microseconds=(delta).microseconds))
                )
            self.pr_msg(tabulate(t, headers=['user', 'start', 'duration']))
            return

        if args.func == 'reserve' or args.func == 'update':
            if args.func == 'reserve':
                if 'user' in r:
                    self.pr_msg(TmMsg.in_use(args.node, r['user']))
                    return
                elif self.curuser == 'root':
                    self.pr_msg('root cannot reserve nodes')
                    return
            elif args.func == 'update':
                if not self.owner_or_root(args.node):
                    return

            try:
                dt = datetime.strptime(args.expire, dtfmt).date()
            except(ValueError):
                self.pr_msg('date format must be dd/mm/yy')
                return
            today = now.date()
            if dt < today:
                self.pr_msg('date must be on or later than today')
                return
            latest = (now + timedelta(days=MAXDAYS)).date()
            if dt > latest:
                dt = latest
                self.pr_msg('set the maximum duration {} days'.format(MAXDAYS))

            d = {'user':getpass.getuser(), 'expire': dt.strftime(dtfmt)}
            if args.func == 'reserve':
                if self.is_bootable(r):
                    if not self.reset_node(args.node, r['mac'], self.curuser):
                        self.pr_msg('{}: cannot create link'.format(args.node))
                        return
                # create or append to the history
                h = r['history'] if 'history' in r else []
                h.append((self.curuser, now.isoformat(), ''))
                d['history'] = h

            self.db.update(d, Query().node == args.node)
        else: # release
            if not self.owner_or_root(args.node):
                return
            self.do_release(r, now)
        self.pr_msg(TmMsg.success(args.node, args.func))

    def network(self, argv):
        parser = ArgumentParser(description="tm-net - "
            "experimental network interface helper", usage='tm network COMMAND [<args>]')
        subparsers = parser.add_subparsers(title='COMMAND')
        for cmd in ('show',):
            p = subparsers.add_parser(cmd,
                    usage='tm network {} [<args>]'.format(cmd))
            if cmd == 'show':
                p.add_argument('--node', type=str, help='--node NODE')
            p.set_defaults(func=cmd)
        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'):
            parser.print_help()
            return

        for nn in NETWORKNODE:
            ans = self.get_db(node=nn)[0]
            if not 'misc' in ans:
                self.pr_msg('{} does not have network information'.format(nn))
                continue
            for i in ans['misc']:
                if args.node is not None:
                    if i['node'] != args.node:
                        continue
                print(i)
        return

    def inventory(self, argv):
        parser = ArgumentParser(description="tm-inventory - "
            "node metadata management", usage='tm inventory COMMAND [<args>]')
        subparsers = parser.add_subparsers(title='COMMAND')
        for cmd in ('add', 'update', 'delete', 'show'):
            p = subparsers.add_parser(cmd,
                    usage='tm inventory {} [<args>] <node>'.format(cmd))
            if cmd == 'show':
                p.add_argument('--node', type=str, help=namehelp)
                p.add_argument('--addrs', action='store_true',
                        help='management addresses') 
                p.add_argument('--devices', action='store_true',
                        help='I/O peripherals') 
                p.add_argument('--reservations', action='store_true',
                        help='reservations') 
                p.add_argument('--misc', type=str, help='--misc NODE')
            elif cmd == 'delete':
                p.add_argument('node', type=str, help=namehelp)
            else:
                lm = lambda o, t, h: p.add_argument(o, type=t, help=h)
                lm('--mac', str, 'MAC addr (e.g., 00:00:00:00:00:00)')
                lm('--ip', str, 'IPv4 addr (e.g., 192.168.0.2)')
                lm('--ipmipass', str, 'IPMI user,pass (e.g., ADMIN,ADMIN)')
                lm('--cpu', str, 'CPU (e.g., Xeon E3-1220v3)')
                lm('--ram', int, 'RAM in GB (e.g., 64)')
                lm('--nic', str, '(non-boot) NIC (e.g., Intel X520-SR2)')
                lm('--disk', str, 'Disk (e.g., Samsung Evo 870 256GB)')
                lm('--note', str, 'Note (e.g., PCIe slot 1 is broken)')
                lm('--ipmiaddr', str, 'IPMI address (e.g., if not ip+100)')
                lm('--chassis', str, 'Chassis (e.g., SMC 6029P-TRT)')
                lm('--misc', str,'func:args to retrieve info for non-regular '
                    'server (e.g., mlx_interfaces:mellanox2)')
                lm('--owner', str, 'Hardware owner (e.g., Michio Honda)')
                p.add_argument('node', type=str, help=namehelp)
            p.set_defaults(func=cmd)

        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'): # XXX
            parser.print_help()
            return

        # XXX
        if args.func == 'show' and args.misc:
            args.node = args.misc

        ans = self.get_db(node=args.node)

        if args.func == 'delete':
            if ans is None:
                self.pr_msg(TmMsg.not_in_inventory(args.node))
                return
            node = ans[0]
            if 'user' in node:
                self.pr_msg(TmMsg.in_use(args.node, node['user']))
                return
            self.db.remove(doc_ids=[node.doc_id,])
            self.pr_msg(TmMsg.success(args.node, args.func))

        elif args.func in ('add', 'update'):
            if args.func == 'add':
                if ans:
                    self.pr_msg('{}: already exist'.format(args.node))
                    return
            else:
                node = ans[0]
            if args.mac and args.mac != '':
                if not self.is_mac(args.mac):
                    self.pr_msg('{}: invalid MAC address'.format(args.node))
                    return
            if args.ip and args.ip != '':
                if not self.is_ipaddr(args.ip):
                    self.pr_msg('{}: invalid IP address'.format(args.node))
                    return
            if args.ipmiaddr and args.ipmiaddr != '':
                if not self.is_ipaddr(args.ipmiaddr):
                    self.pr_msg('{}: invalid IPMI address'.format(args.node))
                    return
            if args.ipmipass and args.ipmipass != '':
                if not self.is_ipmipass(args.ipmipass):
                    self.pr_msg('{}: IPMI login must be USER,PASS'.format(
                        args.node))
                    return
            if args.misc and args.misc != '':
                # so far this is only option
                miscval, *miscargs = args.misc.split(':')
                try:
                    f = getattr(self, miscval)
                    args.misc = f(*miscargs)
                except:
                    self.pr_msg('{}: failed {}({})'.format(
                        args.node, miscval, *miscargs))
                    return

            d = {k:v for k, v in vars(args).items() if v is not None}
            del d['func']
            del_keys = [] # also prevent empty value from being added
            for k, v in d.items():
                if v == '':
                    del_keys.append(k)
                elif not k in ('ram', 'ipmipass', 'misc', 'note'):
                    if search(',', v):
                        d[k] = v.replace(',', '\n')
            d = {k:v for k, v in d.items() if k not in del_keys}
            if args.func == 'update':
                del d['node']
                self.db.update(d, Query().node == args.node)
                for k in (k for k in del_keys if k in node):
                    self.db.update(delete(k), Query().node == args.node)
            else:
                self.db.insert(d)

            self.pr_msg(TmMsg.success(args.node, args.func))

        elif args.func == 'show':
            if ans is None:
                self.pr_msg(TmMsg.not_in_inventory(args.node) if args.node
                        else TmMsg.empty_db())
            if args.misc:
                # misc always has node
                self.pr_msg(ans[0]['misc'] if 'misc' in ans[0]
                    else '{} no entry'.format(args.node))
                return

            dics = sorted(ans, key=itemgetter('node'))
            # Add extra info
            for d in dics:
                if 'user' in d:
                    d['email'] = self.get_email(d['user'])

            ks = [i for s in [list(d.keys()) for d in dics] for i in s]
            reorders = ['node', 'mac', 'ip', 'ipmiaddr', 'ipmipass',
                    'chassis', 'cpu', 'ram', 'nic', 'disk',
                    'user', 'expire', 'email', 'owner', 'note']
            cls = [i for i in reorders if i in list(set(ks))]
            for a in ('addrs', 'devices', 'reservations'):
                if not getattr(args, a):
                    cls = [c for c in cls if c not in getattr(self, a)]
            newdics = []
            for d in dics:
                newdics.append({k: d[k] for k in cls if k in d})
            self.pr_msg(tabulate(newdics, headers='keys'))

    def power(self, argv):
        parser = ArgumentParser(description="tm-power - power management",
                    usage='tm power COMMAND <node>')
        parser.add_argument('command', metavar='COMMAND', type=str,
        choices=['status', 'poweron', 'poweroff', 'restart', 'reset'],
                help='{status|poweron|poweroff|restart|reset}')
        parser.add_argument('node', type=str, help=namehelp)
        args = parser.parse_args(argv[2:])
        r = self.do_ipmi(args.node, args.command, args.command == 'status')
        self.pr_msg(r)

    def console(self, argv):
        parser = ArgumentParser(description="tm-console - access console.",
                    usage='tm console <node>')
        parser.add_argument('node', type=str, help=namehelp)
        args = parser.parse_args(argv[2:])
        self.do_ipmi(args.node, 'console', False)

    def user(self, argv):
        parser = ArgumentParser(description="tm-user - user management",
                    usage='tm user COMMAND <user>')
        parser.add_argument('command', metavar='COMMAND', type=str,
                            choices=['add', 'delete', 'reset'],
                            help='{add|delete|reset}')
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

        if not args.command == 'reset':
            # make sure no leftovers
            for p in dirs:
                d = Path(self.tftpboot)/p/user
                if d.exists():
                    self.pr_msg('{} exists'.format(d))
                    return

            # create homes
            for p in dirs:
                d = Path(self.tftpboot)/p/user
                c = 'mkdir -m 755 {}'.format(d)
                r = self.run(c)
                if r.returncode != 0:
                    self.pr_msg('error in {}'.format(c))
                    return
                r = self.run('chown {}:{} {}'.format(user, user, d))

            # create the file system
            p = Path(self.filesystems)
            ud = p/user
            cmd = 'tar xpf {}.tar.gz -C {}'.format(p/'base'/self.fsversion, ud)
            self.run(cmd)
            self.run('chown {}:{} {}'.format(user, user, ud/self.fsversion))
            self.pr_msg(TmMsg.success('user', 'add'))

        if args.command == 'reset':
            p = Path(self.tftpboot)/'loaders/'/user
            subprocess.run('rm -rf {}/n* {}/default {}/default.arm64'.format(
                p, p, p), shell=True)

        self.init_loaders(user)

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
        src = 'src'
        dst = 'dst'
        fslst = []
        fp = Path(self.filesystems)
        fpname = 'name in {}'.format(fp/u)
        for cmd in ('clone', 'new', 'delete', 'archive', 'restore'):
            p = subparsers.add_parser(cmd,
                    usage='tm filesystem {}'.format(cmd))
            if cmd in ('new', 'clone', 'delete', 'archive', 'restore'):
                if cmd == 'restore':
                    h = 'absolute path of the filesystem tarball (.tar.gz)'
                elif cmd == 'new':
                    h = 'image in {}: '.format(fp/'base')
                    fslst = [str(x.name) for x in (fp/'base').iterdir()
                            if re.search('.tar.gz$', str(x))]
                    h += ' '.join(fslst)
                else:
                    h = fpname
                p.add_argument(src, type=str, help=h)
                p.usage += ' {}'.format(src)

            if cmd in ('new', 'clone', 'restore'):
                p.add_argument(dst, type=str, help=fpname)
                p.usage += ' {}'.format(dst)

            p.usage += ' {}'.format('[-h|--help]')
            p.set_defaults(func=cmd)
        args = parser.parse_args(argv[2:])
        if not hasattr(args, 'func'): # XXX
            parser.print_help()
            return

        # validate src
        srcp = None
        if args.func == 'new':
            if args.src not in fslst:
                self.pr_msg("{} is not available".format(args.src))
                return
            srcp = fp/'base'/args.src
        elif args.func == 'restore':
            srcp = Path(args.src)
        else:
            srcp = fp/u/args.src
        if not srcp.exists():
            self.pr_msg("{} doesn't exist".format(srcp))
            return

        # validate dst
        dstp = None
        if args.func in ('new', 'clone', 'restore', 'archive'):
            if args.func == 'archive':
                dstp = Path(str(srcp)+'.tar.gz')
            else:
                if '/' in args.dst:
                    self.pr_msg('provide the name only (no full path)')
                    return
                dstp = fp/u/args.dst
            if dstp.exists():
                self.pr_msg("{} already exists".format(dstp))
                return

        if self.sudo_user is None:
            self.pr_msg(TmMsg.non_root(args.func))
            return
        u = self.sudo_user

        if args.func == 'delete':
            cmd = 'rm -rf {}'.format(srcp)
        elif args.func == 'clone':
            cmd = 'cp -Rp {} {}'.format(srcp, dstp)
        elif args.func == 'archive':
            cmd = 'tar -acpf {} -C {} {}'.format(dstp, srcp.parent, srcp.name)
        elif args.func == 'restore' or args.func == 'new':
            cmd = 'mkdir {}'.format(dstp)
            print(cmd)
            self.run(cmd)
            cmd = 'tar xpf {} -C {} --strip-components 1'.format(srcp, dstp)
        print(cmd)
        self.run(cmd)
        if cmd != 'delete':
            return
        cmd = 'chown {}:{} {}'.format(self.sudo_user, self.sudo_user, dstp)
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
        c = re.compile('^(?:[0-9a-f]{2}[:-]){5}(?:[0-9a-f]{2})$')
        return True if c.match(mac) else False

    def is_ipaddr(self, ip):
        try:
            IPv4Address(ip)
            return True
        except:
            return False

    def is_ipmipass(self, userpass):
        l = userpass.split(',')
        if len(l) != 2:
            return False
        elif len(l[0]) > 8 or len(l[1]) > 12:
            return False
        return True

    @staticmethod
    def islink(p):
        # d.exists() doesn't work for broken symlink (missing user config file)
        try:
            p.lstat()
            return True
        except:
            return False

    def set_link(self, src, dst):
        if not self.islink(dst):
            return False
        try:
            dst.unlink()
        except:
            print('WARNING: cannot remove the link {}'.format(dst))
        try:
            dst.symlink_to(src)
            return True
        except:
            print('WARNING: failed to create a link to'.format(src))
            return False

    def reset_node(self, node, mac, user):
        boot = GRUB_LINUX_AA64 if self.get_aa64(node) else GRUB_LINUX_X64
        self.set_link(boot, Path(self.dhcpboot)/node) # XXX ignore error
        return self.set_link(Path('../')/'loaders'/user/node, self.grubpath/mac)

    def is_bootable(self, ne):
        if not all(e in ne for e in ('mac', 'ip', 'ipmiaddr', 'ipmipass')):
            return False
        return True if self.islink(self.grubpath/(ne['mac'])) else False

    def do_release(self, node, now):
        if 'history' in node:
            h = node['history']
            if h[-1][0] != self.curuser:
                # admin might release the reservation
                self.pr_msg('current entry {} but now {}'.format(h[-1][0],
                    self.curuser))
            h[-1][2] = now.isoformat()
            self.db.update({'history': h}, Query().node == node['user'])
        if self.is_bootable(node):
            if not self.test:
                self.power(split('tm power poweroff {}'.format(node['node'])))
            r = self.reset_node(node['node'], node['mac'], 'base')
            if not r:
                self.pr_msg('{}: cannot restore symlink for {}'.format(node,
                    node['mac']))

        for e in ['user', 'expire', 'email']:
            try:
                self.db.update(delete(e), Query().node == node['node'])
            except(KeyError):
                if e == 'email': # new version doesn't record email
                    pass

    def init_loaders(self, user):
        def setdirids(d):
            st = os.stat(d)
            os.setgid(st.st_gid)
            os.setuid(st.st_uid)
        # copy the configuration files
        p = Path(self.tftpboot)/'loaders'
        d = p/'base'
        sed = 'sed' if self.os == 'Linux' else 'gsed'
        for i in ('default', 'default.arm64'):
            c = 'cp {} {}'.format(d/i, p/user)
            r = subprocess.run(split(c), preexec_fn=setdirids(p/user))
            if r.returncode != 0:
                self.pr_msg('error in {}'.format(c))
                return False
            # make it writable
            c1 = '{} -i "s/{}/{}/g" {}'.format(sed, '\${roparm} ', '', p/user/i)
            # point to own images
            c2 = '{} -i "s@{}@{}@g" {}'.format(sed, 'filesystems/base',
                    'filesystems/{}'.format(user), p/user/i)
            for c in (c1, c2):
                r = subprocess.run(split(c))
        for i in d.iterdir():
            if re.match(r'^n\d{2}$', i.name) and i.is_symlink(): # XXX
                c = 'ln -sf {} {}'.format(i.readlink(), i.name)
                subprocess.run(split(c), cwd=p/user, stdout=subprocess.DEVNULL)

    def get_db_from_user(self, user):
        res = [self.db.get(Query().user == user)]
        return None if res[0] is None else res

    def get_db(self, node=None):
        if node:
            res = [self.db.get(Query().node == node)]
            return None if res[0] is None else res
        res = self.db.all()
        return None if len(res) == 0 else res

    def do_ipmi(self, node, command, noowner):
        if not noowner and not self.owner_or_root(node, needuser=False):
            self.pr_msg('Invalid user')
            return
        addr = self.get_addrs(node)[1]
        if not addr:
            self.pr_msg(TmMsg.not_in_inventory(node))
            return
        if not self.is_reachable(addr):
            self.pr_msg('{}: IPMI address unreachable'.format(node))
            return
        userpass = self.db.get(Query().node == node)['ipmipass'].split(',')
        cmd = 'ipmitool -I lanplus -C 3 -H {} -U {} -P {} '.format(
                addr, userpass[0], userpass[1])
        console = command == 'console'
        if console:
            subcmd = 'sol activate'
        else:
            d = {'status': 'status', 'poweroff': 'off', 'poweron': 'on',
                    'restart': 'cycle', 'reset': 'reset'}
            subcmd = 'chassis power {}'.format(d[command])
        cmd += subcmd
        r = subprocess.run(split(cmd), capture_output=(not console))
        return None if r.stdout is None else r.stdout.decode().strip()

    @staticmethod
    def get_filesystems(path):
        return [x for x in path.iterdir() if re.search('.tar.gz$', str(x))]

    # XXX
    def get_aa64(self, node):
        r = self.db.get(Query().node == node)
        return True if re.search('Neoverse', r['cpu']) else False

    def pr_msg(self, msg):
        self.output = msg

    @staticmethod
    def is_reachable(addr):
        cmd = 'ping -c 1 {}'.format(addr)
        retry = 2
        while retry:
            retry -= 1
            try:
                ret = subprocess.call(split(cmd), stdout=subprocess.DEVNULL)
                if ret == 0:
                    return True
            except(OSError):
                print('OSError')
        return False

    @staticmethod
    def get_email(name):
        try:
            with open('/etc/passwd', 'r') as f:
                for l in f:
                    l1 = l.split(':')
                    if l1[0] == name:
                        l2 = l1[4].split(',')
                        return l2[4]
            return None
        except FileNotFoundError:
            return None

    @staticmethod
    def mlnx_interfaces(name):
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(name, username="admin", password="admin")
        chan = client.invoke_shell(height=512)
        chan.settimeout(10)
        chan.sendall('show interfaces status \r\n')
        sheet_str = ""
        while (sheet_str.count(name) < 2):
            sheet_str += chan.recv(4096).decode('utf-8')
        sheet_str = sheet_str.replace(' \x08', '')
        r = search('mgmt0', sheet_str)
        sheet_str = r.string[r.start():]
        r = search(name, sheet_str)
        sheet_str = r.string[:r.start()]
        l = []
        for i in [i.strip() for i in sheet_str.split('\r\n')
                if re.match('Eth', i)]:
            i = sub('\s+', ' ', i)
            i = sub('\(.*?\)', '', i)
            i = sub('-', '', i)
            cols = re.split(' ', i)
            if not search(':', cols[5]):
                continue
            trail = '0' if cols[0].count('/') == 1 else ''
            l.append({
              'interface': cols[0], 'status': cols[1], 'speed': cols[3],
              'node': cols[5].split(':')[0], 'ifname': cols[5].split(':')[1],
              'ipaddr': '192.168.11.'+cols[0].replace('Eth1/', '').replace('/',
                    '') + trail + '/24'
                })
        return l

    @staticmethod
    def cumulus_interfaces(name):
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(name, username="cumulus", password="noplab20")
        _, stdout, _ = client.exec_command('net show interface alias')
        l = []
        for i in stdout:
            if not re.search('swp', i):
                continue
            i2 = i.split()
            if len(i2) != 4:
                continue
            if re.search('-tbd', i2[3]):
                continue
            if re.match('swp31s', i2[1]):
                off = 131 + int(i2[1][6])
            elif re.match('swp32s', i2[1]):
                off = 135 + int(i2[1][6])
            else:
                off = int(i2[1][3:])
            l.append({
                'interface': i2[1], 'status': i2[0], 'speed': 'N/A',
                'node': i2[3].split(':')[0], 'ifname': i2[3].split(':')[1],
                'ipaddr': '192.168.11.{}/24'.format(off)
                })
        return l

if __name__ == '__main__':
    print(Tm(sys.argv).output)

