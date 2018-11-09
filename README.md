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

## How To Use It ##

``` sh
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

Here is the program's help message.

```
$ ./makepw.py --help
usage: makepw.py [-h] [--iterations ITERS] [--site SITE] [--extra] [--old]
                 [--no-check]

Generate a site password from a master password and a site name.

optional arguments:
  -h, --help            show this help message and exit
  --iterations ITERS, -i ITERS
                        Number of hash iterations. Defaults to 200000. For the
                        original behavior of a non-iterated hash, use an
                        iteration count of 0.
  --site SITE, -s SITE  Last two components of site domain name (aka
                        slashdot.org).
  --extra, -e           Add just a few more bits of entropy to the result
                        while still satisfying the requires of both upper and
                        lowercase, a digit and a symbol.
  --old, -o             Use old non-PBKDF2 function for generating the
                        password.
  --no-check, -n        Do not print out hash for check_site site. This hash
                        can help you tell if you entered the wrong password.
```

## How It Works ##

It uses the PKCS#5 v2.0 PBKDF2 with a large (but configurable) number
of iterations to make sure that even if an attacker manages to get the
plaintext password for a given site, it will be practically impossible
for them to reverse the hash and figure out the master password.

It has a small bug in which it skips 'Z', 'z' and '9' for generating the
uppercase, lowercase and digit characters. This bug should be faithfully
replicated to all the various implementations.
