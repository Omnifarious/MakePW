import makepw
import pytest

def test_has_main():
    assert(getattr(makepw, 'main'))

def test_has_pbkdf2():
    assert(getattr(makepw, 'pbkdf2'))

pwgen_results = [
    (makepw.pbkdf2, b'\x8a\x1e\xd4 XPK\xea\xcc\xec[>n"\xdc\x05V\xfa\x14\x7f\x95\x1b\x10H\x0f[\xc6]\xc496\x00'),
    (makepw.not_pbkdf2, b'\xa7\xdb\x1bH\xc6\xddW\xc3g\x12]\xc2B\xb2\x08\x11\x88[\xcd-WF\xc9\xb4\xfb\xd4\x94\x90\x07\xddi\x89')
    ]

@pytest.mark.parametrize("hasher,expected", pwgen_results)
def test_hashers(hasher, expected):
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
