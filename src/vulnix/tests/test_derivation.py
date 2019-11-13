from vulnix.vulnerability import Vulnerability
from vulnix.derivation import Derive, split_name, load, SkipDrv
import os
import pkg_resources
import pytest
import tempfile

V = Vulnerability


def drv(fixture):
    return load(pkg_resources.resource_filename(
        'vulnix', 'tests/fixtures/{}.drv'.format(fixture)))


def test_load_drv_explicit_version():
    d = drv('cyrus-sasl-2.5.10')
    assert d.pname == 'cyrus-sasl'
    assert d.version == '2.5.10'


def test_should_not_load_arbitrary_code():
    with tempfile.NamedTemporaryFile(prefix='security_breach') as b:
        with tempfile.NamedTemporaryFile(prefix='evil_eval', mode='w') as f:
            print("""
Derive(envVars={{'name': str((lambda: open('{}', 'w').write('shellcode'))())}})
""".format(b.name), file=f)
            f.flush()
            with pytest.raises(NameError):
                load(f.name)
            assert os.path.getsize(b.name) == 0


def test_split_name():
    assert split_name('network-2.6.3.2-r1.cabal') == (
        'network', '2.6.3.2-r1.cabal')
    assert split_name('python2.7-pytest-runner-2.6.2.drv') == (
        'python2.7-pytest-runner', '2.6.2')
    assert split_name('hook.drv') == ('hook', None)


def test_split_nameversion():
    d = Derive(envVars={'name': 'bundler-1.10.5-0'})
    assert d.pname == 'bundler'
    assert d.version == '1.10.5-0'


def test_split_name_noversion():
    with pytest.raises(SkipDrv):
        Derive(envVars={'name': 'hook'})


def test_guess_cves_from_direct_patches_bzip2():
    deriv = drv('bzip2-1.0.6.0.1')
    assert {'CVE-2016-3189'} == deriv.applied_patches()


def test_guess_cves_from_fetchpatch():
    deriv = drv('cpio-2.12')
    assert {'CVE-2015-1197', 'CVE-2016-2037'} == deriv.applied_patches()


def test_patches_with_multiple_cves():
    deriv = drv('audiofile-0.3.6')
    assert {
        'CVE-2015-7747',
        'CVE-2017-6827',
        'CVE-2017-6828',
        'CVE-2017-6829',
        'CVE-2017-6830',
        'CVE-2017-6831',
        'CVE-2017-6832',
        'CVE-2017-6833',
        'CVE-2017-6834',
        'CVE-2017-6835',
        'CVE-2017-6836',
        'CVE-2017-6837',
        'CVE-2017-6838',
        'CVE-2017-6839',
    } == deriv.applied_patches()


def test_check_returns_cves(nvd):
    """Test for CVE-2016-9844 which is listed but has a patch."""
    nvd.update()
    d = drv('transmission-1.91')
    assert d.check(nvd) == {
        V('CVE-2010-0748', cvssv3=9.8), V('CVE-2010-0749', cvssv3=5.3)
    }


def test_ignore_patched_cves_during_check(nvd):
    """Test for CVE-2016-9844 which is listed but has a patch."""
    nvd.update()
    d = drv('unzip-6.0')
    assert set() == d.check(nvd)


def test_ordering():
    assert Derive(name='python-2.7.14') == Derive(name='python-2.7.14')
    assert Derive(name='python-2.7.14') != Derive(name='python-2.7.13')
    assert Derive(name='coreutils-8.29') < Derive(name='patch-2.7.6')
    assert not Derive(name='python-2.7.5') < Derive(name='patch-2.7.6')
    assert Derive(name='python-2.7.6') > Derive(name='patch-2.7.6')
    assert Derive(name='python-2.7.14') > Derive(name='python-2.7.13')
    assert not Derive(name='patch-2.7.14') > Derive(name='python-2.7.13')
    assert not Derive(name='python-2.7.13') > Derive(name='python-2.7.14')
    assert Derive(name='openssl-1.0.1d') < Derive(name='openssl-1.0.1e')


def test_structured_attrs():
    d = drv('structured-attrs-1')
    assert d.name == 'structured-attrs-1'


def test_product_candidates():
    assert ['linux-kernel', 'linux_kernel'] == list(Derive(
        name='linux-kernel-4.0').product_candidates())
    assert [
        'Email-Address',
        'Email_Address',
        'email-address',
        'email_address',
    ] == list(Derive(name='Email-Address-1').product_candidates())
