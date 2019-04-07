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

# The following list is a bzip2 compressed and base64 encoded version of the
# list that can be fetched from the following URL:
#
# https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt
#
word_data = \
"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"

if __name__ == '__main__':
    entrypoint()
