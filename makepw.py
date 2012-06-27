#!/usr/bin/python

import binascii
import hmac
import hashlib
import getpass
import argparse
import sys

try:
    readstr = raw_input
except NameError:
    readstr = input

def pbkdf2(key, salt, iters):
    try:
        irange = xrange
    except NameError:
        irange = range
    if iters <= 0:
        raise RuntimeError("Too few iterations.")
    hmod = hashlib.sha256
    hmac_con = hmac.HMAC
    for i in irange(0, iters):
        hasher = hmac_con(key=key, digestmod=hmod)
        hasher.update(salt)
        salt = hasher.digest()
    return salt

def bytes_as_int(bstr):
    try:
        return int.from_bytes(bstr, 'big')
    except AttributeError:
        return int(binascii.b2a_hex(bstr), 16)

def mk_arg_parser():
    parser = argparse.ArgumentParser(description="Generate a site password "
                                     "from a master password and a site name.")
    parser.add_argument('--iterations', '-i',
                        metavar='ITERS', type=int, default=200000,
                        help="Number of hash iterations. Defaults to 200000. "
                        "For the original behavior of a non-iterated hash, "
                        "use an iteration count of 0.")
    parser.add_argument('--site', '-s',
                        metavar='SITE', type=str,
                        help="Last two components of site domain name "
                        "(aka slashdot.org).")
    parser.add_argument('--extra', '-e', action='store_true', default=False,
                        help="Add just a few more bits of entropy to the "
                        "result while still satisfying the requires of both "
                        "upper and lowercase, a digit and a symbol.")
    return parser

def get_site(argsite):
    if argsite is not None:
        sitename = argsite
    else:
        sitename = readstr("Last two components of site name "
                           "(aka slashdot.org): ")
    return sitename.encode('utf-8')

def gen_short_pw(hashval):
    resultb64 = binascii.b2a_base64(hashval)
    output = b'0' + resultb64[0:5] + b'*' + resultb64[5:10] + b'l'
    return output.decode('ascii')

def gen_long_pw(hashval):
    resultb64 = binascii.b2a_base64(hashval)
    resultint = bytes_as_int(hashval)

    uppercase = ''.join(chr(x) for x in \
                            range(ord(b'A'), ord(b'Z'))).encode('ascii')
    lowercase = ''.join(chr(x) for x in \
                            range(ord(b'a'), ord(b'z'))).encode('ascii')
    digits = ''.join(chr(x) for x \
                         in range(ord(b'0'), ord(b'9'))).encode('ascii')
    symbols = b'*/+'

    size = 11
    split = 6

    if len(frozenset(uppercase) & frozenset(resultb64[0:size])) > 0:
        letterchoices = lowercase
    else:
        letterchoices = uppercase
    letter = resultint % len(letterchoices)
    resultint = resultint // len(letterchoices)
    symbol = resultint % len(symbols)
    resultint = resultint // len(symbols)
    digit = resultint % len(digits)
    output = digits[digit:digit+1] + resultb64[0:split] + \
        symbols[symbol:symbol+1] + resultb64[split:size] + \
        letterchoices[letter:letter+1]
    return output.decode('ascii')

def main(argv):
    args = mk_arg_parser().parse_args(argv)
    key = getpass.getpass().encode('utf-8')
    sitename = get_site(args.site)

    if args.iterations == 0:
        hasher = hmac.HMAC(key=key, digestmod=hashlib.sha256)
        hasher.update(sitename)
        result = hasher.digest()
    else:
        result = pbkdf2(key, sitename, args.iterations)
    if not args.extra:
        result = gen_short_pw(result)
    else:
        result = gen_long_pw(result)
    print(result)

if __name__ == '__main__':
    main(sys.argv[1:])
