import pytest
from tm import Tm, TmMsg
from shlex import split
from re import search
from datetime import datetime, timedelta
import getpass
from pathlib import Path

n01 = 'tm inventory add --mac 00:00:00:00:12:36 --ip=192.168.0.14 --ipmiaddr 192.168.0.114 --ipmipass root,root --cpu "E3-1220v2" --ram 16 --nic "x520-DA2" n01'
n02 = 'tm inventory add --mac 00:00:00:00:12:37 --ip=192.168.0.15 --ipmiaddr 192.168.0.115 --ipmipass root,root --cpu "E3-1220v2" --ram 8 --nic "x520-DA2" n02'
n03 = 'tm inventory add --mac 00:00:00:00:12:38 --ip=192.168.0.16 --ipmiaddr 192.168.0.116 --ipmipass root,root --cpu "E3-1220v2" --ram 4 --nic "N/A" n03'
addnodes = [n01, n02, n03]

dbfile = 'test_tmdb.json'
tftpboot = 'test_tftpboot'
n1 = 'n01'
n2 = 'n02'

class TmCmd(object):
    def __init__(self, cmd, node=None):
        self.split = split(cmd)
        self.tm, self.cmd, self.sub = self.split[0:3]
        self.args = self.split[3:] if len(self.split) > 3 else []
        self.node = node
    def getcmd(self):
        return self.split
    def getsub(self):
        return self.sub
    def getnode(self):
        return self.node

@pytest.fixture(scope='function', autouse=True)
def test_inventory(tmp_path):

    dbf = tmp_path/dbfile
    tfb = tmp_path/tftpboot
    pxelinux = tfb/'pxelinux.cfg'
    pxelinux.mkdir(parents=True, exist_ok=False)
    loader = tfb/'loaders'/getpass.getuser()
    loader.mkdir(parents=True, exist_ok=False)
    for n in (n1, n2):
        (loader/n).touch(exist_ok=False)
    loader = tfb/'loaders'/'base'
    loader.mkdir(exist_ok=False)
    for n in (n1, n2):
        (loader/n).touch(exist_ok=False)

    testTm = lambda args : Tm(args, dbfile=dbf, tftpboot=tfb, test=True)

    cmd = TmCmd('tm inventory show')
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.empty_db()

    mac = {'good': '00:af:3f:cf:2b:12',
           'bad': ['00:af:3f:cf:2b:1g', '00:af:3f:CF:2b:12',
                   '00:af:3f:cf:12', '00.af.3f.cf.2b.12']}
    ip = {'good': '192.168.56.11', 'bad':['192.168.56.11/24']}
    ipmiaddr = ip
    ipmipass = {'good': 'ADMIN,ADMIN', 'bad': ['ADMIN/ADMIN', 'ADMIN']}
    ram = '64'
    nic = 'X540-DA2'
    cpu = '"Gold 6248"'

    add_cmd = ('tm inventory add --mac {} --ip {} --ipmiaddr {} --ipmipass {} '
               '--ram {} --cpu {} --nic {} {}'
              )
    del_cmd = 'tm inventory delete {}'

    #
    # test MAC addresses
    #
    mactest = lambda mac : add_cmd.format(mac, ip['good'], ipmiaddr['good'],
            ipmipass['good'], ram, cpu, nic, n1)

    for m in mac['bad']:
        cmd = TmCmd(mactest(m), node=n1)
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.bad_mac(cmd.getnode())

    cmd = TmCmd(mactest(mac['good']), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    #
    # test existing node addition
    #
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.node_exist(cmd.getnode())

    #
    # test node removal
    #
    deltest = lambda node : del_cmd.format(node)
    cmd = TmCmd(deltest(n2), node=n2)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.invalid_node(cmd.getnode())

    cmd = TmCmd(deltest(n1), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    #
    # test IP addresses
    #
    iptest = lambda ip : add_cmd.format(mac['good'], ip, ipmiaddr['good'],
            ipmipass['good'], ram, cpu, nic, n1)

    for i in ip['bad']:
        cmd = TmCmd(iptest(i), node=n1)
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.bad_ip(cmd.getnode())

    for t in (iptest(ip['good']), deltest(n1)):
        cmd = TmCmd(t, node=n1)
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    #
    # test IPMI addresses
    #
    ipmiaddrtest = lambda ipmiaddr : add_cmd.format(mac['good'], ip['good'],
            ipmiaddr, ipmipass['good'], ram, cpu, nic, n1)
    for i in ip['bad']:
        cmd = TmCmd(ipmiaddrtest(i), node=n1)
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.bad_ipmi_addr(cmd.getnode())

    cmd = TmCmd(ipmiaddrtest(ip['good']), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    #
    # test IPMI user/pass
    #
    ipmipasstest = lambda ipmipass : add_cmd.format(mac['good'], ip['good'],
            ipmiaddr['good'], ipmipass, ram, cpu, nic, n2)
    for i in ipmipass['bad']:
        cmd = TmCmd(ipmipasstest(i), node=n2)
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.bad_ipmi_pass(cmd.getnode())

    for t in (ipmipasstest(ipmipass['good']), deltest(n2)):
        cmd = TmCmd(t, node=n2)
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    # Add another node
    t = add_cmd.format('00:af:3f:cf:3a:2a', '192.168.56.12', '192.168.56.112',
                        'root,calvin', 32, '"E3-1220v3"', 'x520-DA2', n2)
    cmd = TmCmd(t, node=n2)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    yield()

    # Delete nodes
    for n in (n1, n2):
        cmd = TmCmd(del_cmd.format(n), node=n)
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

def test_reservation(test_inventory, tmp_path):

    dbf = tmp_path/dbfile
    tfb = tmp_path/tftpboot
    testTm = lambda args : Tm(args, dbfile=dbf, tftpboot=tfb, test=True)

    email = 'abc@example.com'
    now = datetime.now().date()
    times = []
    for days in (-1, 1, 10):
        times.append(datetime.strftime(now + timedelta(days=days), '%d/%m/%y'))

    rsv_cmd = 'tm reservation {} {} {} {}'

    cmd = TmCmd(rsv_cmd.format('reserve', n1, times[0], email), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.invalid_date()

    cmd = TmCmd(rsv_cmd.format('reserve', n1, times[1], email), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    # check symlink
    src = tfb/'loaders'/getpass.getuser()/n1
    dst = tfb/'pxelinux.cfg'/'01-00-af-3f-cf-2b-12'
    assert dst.samefile(src)

    cmd = TmCmd(rsv_cmd.format('reserve', n1, times[1], email), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.in_use(cmd.getnode(), getpass.getuser())

    cmd = TmCmd(rsv_cmd.format('update', n1, times[2], ''), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    cmd = TmCmd(rsv_cmd.format('release', n1, '', ''), node=n1)
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    src = tfb/'loaders'/'base'/n1
    dst = tfb/'pxelinux.cfg'/'01-00-af-3f-cf-2b-12'
    assert dst.samefile(src)
