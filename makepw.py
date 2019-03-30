#!/usr/bin/python

# Copyright 2018 by Eric M. Hopper
# Licensed under the GNU Public License version 3 or any later version

from __future__ import print_function

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
import os
try:
    from urllib2 import urlopen
except ImportError:
    # Assume Python3
    from urllib.request import urlopen

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
    key = as_bytes(key)
    salt = as_bytes(salt)
    try:
        iters = int(iters)
    except ValueError:
        raise TypeError("iters must be an integer.")
    if iters <= 0:
        raise ValueError("Too few iterations.")
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
    """An iterated hash function that doesn't follow the PBKDF2 standard.

    This function has been replaced with a PBKDF2 version on the theory that
    the people who created the standard knew what they were doing.

    It's being kept around for old passwords generated using it."""
    try:
        irange = xrange
    except NameError:
        irange = range
    key = as_bytes(key)
    salt = as_bytes(salt)
    try:
        iters = int(iters)
    except ValueError:
        raise TypeError("iters must be an integer.")
    if iters <= 0:
        raise ValueError("Too few iterations.")
    hmac_con = hmac.HMAC
    for i in irange(0, iters):
        hasher = hmac_con(key=key, digestmod=hmod)
        hasher.update(salt)
        salt = hasher.digest()
    return salt


def bytes_as_int(bstr):
    """Convert a bunch of bytes into an int both Python 2 and 3."""
    try:
        return int.from_bytes(bstr, 'big')
    except AttributeError:
        return int(binascii.b2a_hex(bstr), 16)


def as_bytes(arg):
    """Transform any iterable over bytes into bytes."""
    try:
        arg = bytes().join(arg)
    except TypeError:
        args = object()
    if not isinstance(arg, bytes):
        raise TypeError("Expected bytes, got something else.")
    return arg

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
                        help="Unique site or account identifier, usually the"
                        " last two components of site domain name (aka"
                        " slashdot.org).")
    parser.add_argument('--extra', '-e', action='store_true', default=False,
                        help="Backwards compatility - equivalent to "
                        "--format stupid_policy14")
    parser.add_argument('--old', '-o', action='store_true', default=False,
                        help="Use old non-PBKDF2 function for generating the "
                        "password.  Not relevant with -r")
    parser.add_argument('--format', '-f',
                        metavar='FORMAT', type=str, default=None,
                        help="Output format of resulting password.  Defaults"
                        " to 'stupid_policy13'.  Use --list-formats for a"
                        " list of supported formats.")
    parser.add_argument('--list-formats', '-l', action='store_true',
                        default=False,
                        help="Print out a list of supported formats,"
                        " like --help, this short-circuits any other function.")
    parser.add_argument('--random', '-r', action='store_true',
                        help="Use the OS secure random number generation to"
                        " creae a random password instead of asking for a"
                        " master password. Useful for generating master"
                        " passwords, or with the xkcd algorithm. Implies"
                        " --no-check and ignores the site name and --iterations.")
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
    """Generate a 13 character password with 60 bits of entropy that probably
    meets various silly password requirements."""
    hashval = as_bytes(hashval)
    resultb64 = binascii.b2a_base64(hashval)
    output = b'0' + resultb64[0:5] + b'*' + resultb64[5:10] + b'l'
    return output.decode('ascii')

def gen_long_pw(hashval):
    """Generate  a 14 character password with about 75 bits of entropy that
    that almost certainly meets various silly password requirements."""
    hashval = as_bytes(hashval)
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


def gen_xkcd_pw(numwords, randbytes):
    lstfile = urlopen('https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt')
    wordlist = tuple(lstfile.read().split())
    lstfile.close()

    wordlist = tuple(w.decode('utf-8') for w in wordlist if len(w) >= 3)
    randbigint =  bytes_as_int(randbytes)
    pw = u''
    for i in range(0, numwords):
        pw += wordlist[randbigint % len(wordlist)].capitalize()
        randbigint //= len(wordlist)
    return pw


def print_formats():
    print("""List of password formats:
   stupid_policy13 - Alphanumeric characters with at least 1 uppercase,
                     1 lowercase, one number and one symbol.  Designed to satisfy
                     most stupid password policies. About 60 bits of entropy.

   stupid_policy14 - The same as above, buy slightly longer and varied for
                     75 bits of entropy.

   xkcd4           - Four random capitalized common English words of 5 letters
                     or more, chosen from a list of 8813 for 52 bits of
                     entropy. The word list is all words >= 3 letters from
                     https://github.com/first20hours/google-10000-english . The
                     name and idea comes from https://xkcd.com/936

   xkcd5           - Same as previous, but with 5 words instead, for about 66
                     bits of entropy.

   xkcd6           - Same as xkcd4, but with 6 words. Has about 79 bits of
                     entropy.

                   * Note that xkcd passwords have more effective entropy than
                     their 'official' entropy values because an attacker will
                     have to try a lot of passwords where no part of the
                     password comes from a dictionary.
""")
    pass

# https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-usa-no-swears-medium.txt

def random_password_seed(args):
    return os.urandom(32)

def hashed_password_seed(args):
    sitename = get_site(args.site)
    key = getpass.getpass().encode('utf-8')
    if not args.no_check or args.random:
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
    return result

def format_pw(pwfmt, randbytes):
    if pwfmt == 'stupid_policy13':
        return gen_short_pw(randbytes)
    elif pwfmt == 'stupid_policy14':
        return gen_long_pw(randbytes)
    elif pwfmt.startswith('xkcd'):
        try:
            numwords = int(pwfmt[4:])
            if 4 <= numwords <= 6:
                return gen_xkcd_pw(numwords, randbytes)
        except ValueError:
            pass
    print("Unknown format '{}', try `--list-formats` to get a list of valid"
          " formats.".format(pwfmt), file=sys.stderr)
    raise SystemExit(2)

def main(argv):
    args = mk_arg_parser().parse_args(argv)
    if args.list_formats:
        print_formats()
        return

    if args.random:
        result = random_password_seed(args)
    else:
        result = hashed_password_seed(args)

    if args.format:
        result = format_pw(args.format, result)
    elif args.extra:
        result = format_pw("stupid_policy14", result)
    else:
        result = format_pw("stupid_policy13", result)
    print(result)

def entrypoint():
    main(sys.argv[1:])

if __name__ == '__main__':
    entrypoint()

