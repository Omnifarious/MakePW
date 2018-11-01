// Copyright 2018 by Eric M. Hopper
// Licensed under the GNU Public License version 3 or any later version

load('sjcl/sjcl.js')

pbkdf2 = sjcl.misc.pbkdf2;
hashbits_to_b64 = sjcl.codec.base64.fromBits;

function s32bits_to_u16bits(hashbits) {
    var i = 0;
    var o = 0;
    var newbits = new Array(hashbits.length * 2);
    for (; i < hashbits.length; ++i, o += 2) {
        newbits[o] = (hashbits[i] >> 16) & 0xffff;
        newbits[o + 1] = hashbits[i] & 0xffff;
    }
    return newbits;
}

function u16bits_to_s32bits(smallbits) {
    var i = 0;
    var o = 0;
    if (smallbits.length & 1) {
        var newbits = new Array((smallbits.length + 1) / 2);
        newbits[0] = smallbits[0] & 0xffff;
        o = 1;
        i = 1;
    } else {
        var newbits = new Array(smallbits.length / 2);
    }
    while (i < smallbits.length) {
        newbits[o] = ((smallbits[i] & 0xffff) << 16) |
            (smallbits[i + 1] & 0xffff);
        i += 2;
        o += 1;
    }
    return newbits;
}

function divmod(hashbits, num) {
    var i = 0;
    var div = [];
    var tempdiv = 0;
    var tempmod = 0;
    var nextval = 0;
    var newbits = [];
    if (num > 0x7fff) {
        throw "divmod by numbers > 0x7fff not supported.";
    }
    hashbits = s32bits_to_u16bits(hashbits);
    nextval = hashbits[0];
    while (i < hashbits.length) {
        tempmod = nextval % num;
        tempdiv = (nextval - tempmod) / num;
        if ((newbits.length > 0) || (tempdiv != 0)) {
            newbits[newbits.length] = tempdiv;
        }
        ++i;
        if (i < hashbits.length) {
            nextval = (tempmod << 16) | hashbits[i];
        }
    }
    var retval = new Array(2);
    retval[0] = u16bits_to_s32bits(newbits)
    retval[1] = tempmod;
    return retval;
}

function gen_long_pw(hashbits) {
    var resultb64 = hashbits_to_b64(hashbits)

    var charchoices;
    var digits = '012345678'; // Purposefully missing the 9.
    var symbols = '*/+';
    var has_upper = 0;

    var size = 11;
    var split = 6;
    var i = 0;
    var tmp;

    for (i = 0; (i < size) && !has_upper; ++i) {
        // This next comparison is not a bug. Or, rather it's
        // faithfully replicating a bug.
        if ((resultb64[i] >= 'A') && (resultb64[i] < 'Z')) {
            has_upper = 1;
        }
    }
    if (has_upper) {
        // Again, missing the Z on purpose. :-(
        charchoices = 'abcdefghijklmnopqrstuvwxy';
    } else {
        // Again, missing the z on purpose. :-(
        charchoices = 'ABCDEFGHIJKLMNOPQRSTUVWXY';
    }

    tmp = divmod(hashbits, charchoices.length);
    hashbits = tmp[0];
    tmp = tmp[1];

    var lastletter = charchoices.substr(tmp, 1)

    tmp = divmod(hashbits, symbols.length)
    hashbits = tmp[0]
    tmp = tmp[1]

    var middlesymbol = symbols.substr(tmp, 1)

    tmp = divmod(hashbits, digits.length)
    hashbits = tmp[0]
    tmp = tmp[1]

    var firstdigit = digits.substr(tmp, 1)

    var firstpart = resultb64.substring(0, split);
    var secondpart = resultb64.substring(split, size);
    return firstdigit.concat(firstpart).
        concat(middlesymbol).concat(secondpart).concat(lastletter);
}

function makepw(key, salt, iters)
{
    return gen_long_pw(pbkdf2(key, salt, iters))
}
