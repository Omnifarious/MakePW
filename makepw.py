#!/usr/bin/python

# Copyright 2018 by Eric M. Hopper
# Licensed under the GNU Public License version 3 or any later version

"""A utility for generating passwords that pass most sites ridiculous password
rules from a master password using repeated hashing with the site name as a
salt.
"""

__author__ = "Eric M. Hopper"
__copyright__ = "Copyright 2018, Eric Hopper"
__license__ = "GPLv3+"
__version__ = "1.0"

import binascii
import hmac
import hashlib
import getpass
try:
    import argparse
except ImportError:
    import optparse
    argparse = optparse
    optparse.ArgumentParser = optparse.OptionParser
    optparse.ArgumentParser.add_argument = optparse.ArgumentParser.add_option
import sys
import struct

try:
    # Python 2
    readstr = raw_input
    def binxor(a, b):
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))
except NameError:
    # Python 3
    readstr = input
    def binxor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

def pbkdf2(key, salt, iters, hmod=hashlib.sha256):
    """Computes the PKCS#5 v2.0 PBKDF2 function given a key, a salt
    and a number of iterations, and an optional hashing module.  The
    hashing module will be used as the hashing module for HMAC.

    This function only computes one block worth of key material."""
    try:
        # Python 2
        irange = xrange
    except NameError:
        # Python 3
        irange = range
    if iters <= 0:
        raise RuntimeError("Too few iterations.")
    hmac_con = hmac.HMAC
    result = None
    salt = salt + struct.pack("!L", 1)
    for i in irange(0, iters):
        hasher = hmac_con(key=key, digestmod=hmod)
        hasher.update(salt)
        salt = hasher.digest()
        if result is None:
            result = salt
        else:
            result = binxor(result, salt)
    return result

def not_pbkdf2(key, salt, iters, hmod=hashlib.sha256):
    try:
        irange = xrange
    except NameError:
        irange = range
    if iters <= 0:
        raise RuntimeError("Too few iterations.")
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
    parser.add_argument('--old', '-o', action='store_true', default=False,
                        help="Use old non-PBKDF2 function for generating the "
                        "password.")
    parser.add_argument('--no-check', '-n', action='store_true', default=False,
                        help="Do not print out hash for check_site site. "
                        "This hash can help you tell if you entered the "
                        "wrong password.")
    try:
        old = argparse.OptionParser
        old = parser.parse_args
        parser.parse_args = lambda a: old(a)[0]
    except AttributeError:
        pass
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

    if not args.no_check:
        check_result = pbkdf2(key, b'check_site', 100)
        print("check_site hash is: %s" % gen_long_pw(check_result))
    if args.iterations == 0:
        hasher = hmac.HMAC(key=key, digestmod=hashlib.sha256)
        hasher.update(sitename)
        result = hasher.digest()
    elif args.old:
        result = not_pbkdf2(key, sitename, args.iterations)
    else:
        result = pbkdf2(key, sitename, args.iterations)
    if not args.extra:
        result = gen_short_pw(result)
    else:
        result = gen_long_pw(result)
    print(result)

if __name__ == '__main__':
    main(sys.argv[1:])
