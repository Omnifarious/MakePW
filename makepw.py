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

parser = argparse.ArgumentParser(description="Generate a site password from a "
                                 "master password and a site name.")
parser.add_argument('--iterations', '-i',
                    metavar='ITERS', type=int, default=200000,
                    help="Number of hash iterations. Defaults to 200000. For "
                    "the original behavior of a non-iterated hash, use an "
                    "iteration count of 0.")
parser.add_argument('--site', '-s',
                    metavar='SITE', type=str,
                    help="Last two components of site domain name "
                    "(aka slashdot.org).")

args = parser.parse_args(sys.argv[1:])

key = getpass.getpass().encode('utf-8')

if args.site is not None:
    sitename = args.site
else:
    sitename = readstr("Last two components of site name (aka slashdot.org): ")
sitename = sitename.encode('utf-8')

if args.iterations == 0:
    hasher = hmac.HMAC(key=key, digestmod=hashlib.sha256)
    hasher.update(sitename)
    result = hasher.digest()
else:
    result = pbkdf2(key, sitename, args.iterations)
result = binascii.b2a_base64(result).decode('ascii')
print('0' + result[0:5] + '*' + result[5:10] + 'l')
