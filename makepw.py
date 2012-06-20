#!/usr/bin/python

import binascii
import hmac
import hashlib
import getpass

try:
    readstr = raw_input
except NameError:
    readstr = input

hasher = hmac.HMAC(key=getpass.getpass().encode('utf-8'),
                   digestmod=hashlib.sha256)
sitename = readstr("Last two components of site name (aka slashdot.org): ")
hasher.update(sitename.encode('utf-8'))
result = binascii.b2a_base64(hasher.digest()).decode('ascii')
print('0' + result[0:5] + '*' + result[5:10] + 'l')
