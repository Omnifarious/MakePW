import makepw

def test_has_main():
    assert(getattr(makepw, 'main'))

def test_has_pbkdf2():
    assert(getattr(makepw, 'pbkdf2'))

def test_pbkdf2():
    h = makepw.pbkdf2(b'fred', b'barney', 500)
    assert(isinstance(h, bytes))
    assert(h == b'\x8a\x1e\xd4 XPK\xea\xcc\xec[>n"\xdc\x05V\xfa\x14\x7f\x95\x1b\x10H\x0f[\xc6]\xc496\x00')
    j = makepw.pbkdf2(b'fred', b'barney', 499)
    assert(j != h)
    ds = makepw.pbkdf2(b'fred', b'barnex', 500)
    assert(ds != h)
    assert(ds != j)
    dk = makepw.pbkdf2(b'frec', b'barney', 500)
    assert(dk != h)
    assert(dk != j)
    assert(dk != ds)
