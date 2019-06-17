from vulnix.derivation import Derive, split_name, load, NoVersionError
import os
import pkg_resources
import pytest
import tempfile


def fix(fixture):
    return pkg_resources.resource_filename(
        'vulnix', 'tests/fixtures/{}'.format(fixture))


def test_load_drv_explicit_version():
    d = load(fix('cyrus-sasl-2.5.10.drv'))
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
    with pytest.raises(NoVersionError):
        Derive(envVars={'name': 'hook'})


def test_guess_cves_from_direct_patches_bzip2():
    deriv = load(fix('bzip2-1.0.6.0.1.drv'))
    assert {'CVE-2016-3189'} == deriv.patched()


def test_guess_cves_from_fetchpatch():
    deriv = load(fix('cpio-2.12.drv'))
    assert {'CVE-2015-1197', 'CVE-2016-2037'} == deriv.patched()


def test_patches_with_multiple_cves():
    deriv = load(fix('audiofile-0.3.6.drv'))
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
    } == deriv.patched()


def test_ignore_patched_cves_during_check(nvd_modified):
    """Test for CVE-2016-9844 which is listed but has a patch."""
    deriv = load(fix('unzip-6.0.drv'))
    deriv.check(nvd_modified)
    assert set() == deriv.affected_by


def test_ordering():
    assert Derive(name='python-2.7.14') == Derive(name='python-2.7.14')
    assert Derive(name='python-2.7.14') != Derive(name='python-2.7.13')
    assert Derive(
        name='coreutils-8.29', affected_by={'CVE-2017-18018'}
    ) < Derive(
        name='patch-2.7.6', affected_by={'CVE-2018-6952', 'CVE-2018-6951'})
    assert Derive(name='python-2.7.14') > Derive(name='python-2.7.13')
    assert not Derive(name='python-2.7.13') > Derive(name='python-2.7.14')
    assert Derive(
        name='patch-2.7.6', affected_by={'CVE-2018-6951', 'CVE-2018-6952'}
    ) > Derive(
        name='patch-2.7.6', affected_by={'CVE-2018-6951'})


def test_structured_attrs():
    d = load(fix('structured-attrs-1.drv'))
    assert d.name == 'structured-attrs-1'
