import makepw
import pytest

# Copyright 2018 by Eric M. Hopper
# Licensed under the GNU Public License version 3 or any later version

__author__ = "Eric M. Hopper"
__copyright__ = "Copyright 2018, Eric Hopper"
__license__ = "GPLv3+"
__version__ = "1.0"

def test_has_main():
    assert(getattr(makepw, 'main'))

def test_has_pbkdf2():
    assert(getattr(makepw, 'pbkdf2'))

hasher_results = [
    (makepw.pbkdf2, b'\x8a\x1e\xd4 XPK\xea\xcc\xec[>n"\xdc\x05V\xfa\x14\x7f\x95\x1b\x10H\x0f[\xc6]\xc496\x00'),
    (makepw.not_pbkdf2, b'\xa7\xdb\x1bH\xc6\xddW\xc3g\x12]\xc2B\xb2\x08\x11\x88[\xcd-WF\xc9\xb4\xfb\xd4\x94\x90\x07\xddi\x89')
    ]

@pytest.mark.parametrize("hasher,expected", hasher_results)
def test_hasher_results(hasher, expected):
    h = hasher(b'fred', b'barney', 500)
    assert(isinstance(h, bytes))
    assert(h == expected)
    j = hasher(b'fred', b'barney', 499)
    assert(j != h)
    ds = hasher(b'fred', b'barnex', 500)
    assert(ds != h)
    assert(ds != j)
    dk = hasher(b'frec', b'barney', 500)
    assert(dk != h)
    assert(dk != j)
    assert(dk != ds)

@pytest.mark.parametrize("hasher,expected", hasher_results)
def test_hasher_typechecks(hasher, expected):
    # Ignore expected, this is parameterized just for the list of different
    # hashing functions.
    with pytest.raises(TypeError):
        hasher(u'fred', b'barney', 500)
    with pytest.raises(TypeError):
        hasher(b'fred', u'barney', 500)
    with pytest.raises(TypeError):
        hasher(b'fred', b'barney', 'wilma')
    with pytest.raises(ValueError):
        hasher(b'fred', b'barney', 0)
    with pytest.raises(ValueError):
        hasher(b'fred', b'barney', -1)
    hasher(b'fred', b'barney', 1)

def test_short_pw_types():
    with pytest.raises(TypeError):
        makepw.gen_short_pw(u'a nice long string that should be big enough')
    with pytest.raises(TypeError):
        makepw.gen_short_pw(object())
    #with pytest.raises(ValueError):
    #    makepw.gen_short_pw(b'')
    # These need to go in later
    #with pytest.raises(ValueError):
    #    makepw.gen_short_pw(b'1234567')
    makepw.gen_short_pw(b'12345678')

def test_short_pw_results():
    assert(makepw.gen_short_pw(b'\0'*8) == '0AAAAA*AAAAAl')
    assert(makepw.gen_short_pw(b'\xff'*8) == '0/////*/////l')
    assert(makepw.gen_short_pw(b'\x01\x02\x03\x04\x05\x06\x07\x08') == '0AQIDB*AUGBwl')

def test_long_pw_types():
    with pytest.raises(TypeError):
        makepw.gen_long_pw(u'a nice long string that should be big enough')
    with pytest.raises(TypeError):
        makepw.gen_long_pw(object())
    with pytest.raises(TypeError):
        makepw.gen_long_pw(5)
    # These need to go in later
    #with pytest.raises(ValueError):
    #    makepw.gen_long_pw(b'')
    # These need to go in later
    #with pytest.raises(ValueError):
    #    makepw.gen_long_pw(b'123456789')
    makepw.gen_long_pw(b'1234567890')

long_pw_results = [
    (b'\0'*10, '0AAAAAA*AAAAAa'),
    (b'\xff'*10, '7//////*/////A'),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xee ', '0//////*/////A'),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xee\x07', '8//////+/////A'),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xee\x06', '8////////////Y'),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xee\x06', '8////////////Y'),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xeb}', '0//////*/////A'),
    (b'\xff\xff\xff\xff\xff\xff\xff\xff\xeb|', '8//////+/////Y'),
    (b'\xd2)\x1d=T\x90\xed,\xf2\xa9', '50ikdPV/SQ7Szg')
]

@pytest.mark.parametrize("hash,expected", long_pw_results)
def test_long_pw_results(hash, expected):
    assert(makepw.gen_long_pw(hash) == expected)
