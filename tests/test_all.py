from tm import Tm, TmMsg
from shlex import split
from re import search
from datetime import datetime, timedelta
import getpass

n01 = 'tm inventory add --mac 00:00:00:00:12:36 --ip=192.168.0.14 --ipmiaddr 192.168.0.114 --ipmipass root,root --cpu "E3-1220v2" --ram 16 --nic "x520-DA2" n01'
n02 = 'tm inventory add --mac 00:00:00:00:12:37 --ip=192.168.0.15 --ipmiaddr 192.168.0.115 --ipmipass root,root --cpu "E3-1220v2" --ram 8 --nic "x520-DA2" n02'
n03 = 'tm inventory add --mac 00:00:00:00:12:38 --ip=192.168.0.16 --ipmiaddr 192.168.0.116 --ipmipass root,root --cpu "E3-1220v2" --ram 4 --nic "N/A" n03'
addnodes = [n01, n02, n03]

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

dbf = './test_tmdb.json'
tfb = './test_tftpboot'

def test_all():

    testTm = lambda args : Tm(args, dbfile=dbf, tftpboot=tfb, test=True)

    cmd = TmCmd('tm inventory show')
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.empty_db()
    for a in addnodes:
        cmd = TmCmd(a, node=split(a)[-1])
        out = testTm(cmd.getcmd()).output
        assert out == TmMsg.success(cmd.getnode(), cmd.getsub())
    cmd = TmCmd('tm inventory show --addr --devices')
    out = testTm(cmd.getcmd()).output
    for n in ['n01', 'n02', 'n03']:
        assert n in out['node'].values
        for i in ['mac', 'ip', 'ipmiaddr', 'ipmipass', 'cpu', 'ram']:
            assert len(out[i].values) == 3

    now = datetime.now().date()
    nowm1 = now + timedelta(days=-1)
    nowm1_s = datetime.strftime(nowm1, '%d/%m/%y')
    nowp1 = now + timedelta(days=1)
    nowp1_s = datetime.strftime(nowp1, '%d/%m/%y')
    nowp10 = now + timedelta(days=10)
    nowp10_s = datetime.strftime(nowp10, '%d/%m/%y')

    cmd = TmCmd('tm reservation reserve n01 {}'.format(nowm1_s))
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.invalid_date()

    cmd = TmCmd('tm reservation reserve n01 {}'.format(nowp1_s), node='n01')
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    cmd = TmCmd('tm reservation reserve n01 {}'.format(nowp1_s), node='n01')
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.in_use(cmd.getnode(), getpass.getuser())

    cmd = TmCmd('tm reservation update n01 {}'.format(nowp10_s), node='n01')
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())

    cmd = TmCmd('tm reservation release n01', node='n01')
    out = testTm(cmd.getcmd()).output
    assert out == TmMsg.success(cmd.getnode(), cmd.getsub())
