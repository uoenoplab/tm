from tm import Tm
import shlex
from re import search
from datetime import datetime, timedelta

n01 = 'tm inventory add --mac 00:00:00:00:12:36 --ip=192.168.0.14 --ipmiaddr 192.168.0.114 --ipmipass root,root --cpu "E3-1220v2" --ram 16 --nic "x520-DA2" n01'
n02 = 'tm inventory add --mac 00:00:00:00:12:37 --ip=192.168.0.15 --ipmiaddr 192.168.0.115 --ipmipass root,root --cpu "E3-1220v2" --ram 8 --nic "x520-DA2" n02'
n03 = 'tm inventory add --mac 00:00:00:00:12:38 --ip=192.168.0.16 --ipmiaddr 192.168.0.116 --ipmipass root,root --cpu "E3-1220v2" --ram 4 --nic "N/A" n03'
addnodes = [n01, n02, n03]

dbf = './test_tmdb.json'
tfb = './test_tftpboot'

ret_rsv_date_past = 'date must be on or later than today'
ret_rsv_in_use = 'node in use'
ret_rsv_success = 'reserve successful'
ret_rsv_update_success = 'update successful'
ret_rsv_release_success = 'release successful'

def test_all():
    out = Tm(shlex.split('tm inventory show'), dbfile=dbf, tftpboot=tfb).output
    assert search('no db entry', out)

    for a in addnodes:
        out = Tm(shlex.split(a), dbfile=dbf, tftpboot=tfb).output
        assert search('success', out)
    out = Tm(shlex.split('tm inventory show --addr --devices'), dbfile=dbf, tftpboot=tfb).output
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

    out = Tm(shlex.split('tm reservation reserve n01 {}'.format(nowm1_s)),
            dbfile=dbf, tftpboot=tfb).output
    assert search(ret_rsv_date_past, out)

    out = Tm(shlex.split('tm reservation reserve n01 {}'.format(nowp1_s)),
            dbfile=dbf, tftpboot=tfb).output
    assert search(ret_rsv_success, out)

    out = Tm(shlex.split('tm reservation reserve n01 {}'.format(nowm1_s)),
            dbfile=dbf, tftpboot=tfb).output
    assert search(ret_rsv_in_use, out)

    out = Tm(shlex.split('tm reservation update n01 {}'.format(nowp10_s)),
            dbfile=dbf, tftpboot=tfb).output
    assert search(ret_rsv_update_success, out)

    out = Tm(shlex.split('tm reservation release n01'),
            dbfile=dbf, tftpboot=tfb).output
    assert search(ret_rsv_release_success, out)
