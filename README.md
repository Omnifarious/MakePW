MakePW Secure Password Generator
================================

## Overview ##

A Python command line utility I put together so I can use a master
password and have it generate a site specific password for each site
that needs a password. I'm in the process of adding a Javascript
implementation for use in a web browser and and an Android applet
implementation.

The passwords generated are carefully massaged to try to fit just
about every site's password requirements and keep at least 60 bits of
entropy in every password.

It should work both in Python 2.7 and any version of Python 3.

## How To Use It ##

### Example Usage ###

```text
$ ./makepw.py -e --site=google.com
Password: 
check_site hash is: 4Uwtzpj+3Jt0Jp
6TsgvLT+vbXZSw
```

The `check_site hash` uses a fixed and special site name to hash your
master password.  This allows you to see if you've mistyped your
password without revealing what it is.  The `check_site hash` should
always the same for a given master password.

In this case, `6TsgvLT+vbXZSw` is the password you should use for
Google.  You can specify whatever you want to for the site name.  It is
mixed with your master password in an irreversible way to generate the
site password.

### Program Help Message ###

```text
$ ./makepw.py --help
usage: makepw.py [-h] [--iterations ITERS] [--site SITE] [--extra] [--old]
                 [--format FORMAT] [--list-formats] [--random] [--no-check]

Generate a site password from a master password and a site name.

optional arguments:
  -h, --help            show this help message and exit
  --iterations ITERS, -i ITERS
                        Number of hash iterations. Defaults to 200000. For the
                        original behavior of a non-iterated hash, use an
                        iteration count of 0.
  --site SITE, -s SITE  Unique site or account identifier, usually the last
                        two components of site domain name (aka slashdot.org).
  --extra, -e           Backwards compatility - equivalent to --format
                        stupid_policy14
  --old, -o             Use old non-PBKDF2 function for generating the
                        password. Not relevant with -r
  --format FORMAT, -f FORMAT
                        Output format of resulting password. Defaults to
                        'stupid_policy13'. Use --list-formats for a list of
                        supported formats.
  --list-formats, -l    Print out a list of supported formats, like --help,
                        this short-circuits any other function.
  --random, -r          Use the OS secure random number generation to creae a
                        random password instead of asking for a master
                        password. Useful for generating master passwords, or
                        with the xkcd algorithm. Implies --no-check and
                        ignores the site name and --iterations.
  --no-check, -n        Do not print out hash for check_site site. This hash
                        can help you tell if you entered the wrong password.
```

## How It Works ##

When not using `--random` mode, it uses the PKCS#5 v2.0 PBKDF2 with a
large (but configurable) number of iterations to make sure that even if
an attacker manages to get the plaintext password for a given site, it
will be practically impossible for them to reverse the hash and figure
out the master password.

## Known Bugs ##

It has a small bug in which it skips 'Z', 'z' and '9' for generating the
uppercase, lowercase and digit characters. When implementing this for
some other language, this this bug should be faithfully replicated to
maintain compatibility and allow people to use any implementation for
re-creating a password they created with a different implementation.
