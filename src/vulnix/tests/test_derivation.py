from pkg_resources import resource_filename
import os
import pytest
import tempfile

from vulnix.derivation import Derive, split_name, load


def tf(fixture):
    return resource_filename('vulnix', 'tests/fixtures/{}'.format(fixture))


def test_load_drv_explicit_version():
    d = load(tf('cyrus-sasl-2.5.10.drv'))
    assert d.pname == 'cyrus-sasl'
    assert d.version == '2.5.10'


def test_product_candidates():
    d = Derive(envVars={'name': 'python2.7-pytest-runner-2.6.2.drv'})
    assert (['python2.7_pytest_runner', 'python2.7_pytest', 'python2.7'] ==
            list(d.product_candidates))


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
    assert split_name('CVE-2017-5526.patch.drv', '5526.patch') == (
        'CVE-2017', '5526.patch')


def test_split_nameversion():
    d = Derive(envVars={'name': 'bundler-1.10.5'})
    assert d.pname == 'bundler'
    assert d.version == '1.10.5'


def test_split_name_noversion():
    d = Derive(envVars={'name': 'hook'})
    assert d.pname == 'hook'
    assert d.version is None


def test_guess_cves_from_direct_patches():
    deriv = load(tf('bzip2-1.0.6.0.1.drv'))
    assert {'CVE-2016-3189'} == deriv.cves()


def test_guess_cves_from_fetchpatch():
    deriv = load(tf('cpio-2.12.drv'))
    assert {'CVE-2015-1197', 'CVE-2016-2037'} == deriv.cves()
