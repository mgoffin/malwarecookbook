#!/usr/bin/python
import struct

def single_byte_xor(buf, key):
    out = ''
    for i in buf:
        out += chr(ord(i) ^ key)
    return out

def single_byte_brute_xor(buf, plntxt, start=None, end=None):
    for key in range (1,255):
        out = ''
        for i in buf:
            out += chr(ord(i) ^ key)
        for p in plntxt:
            if out[start:end].find(p) != -1:
                return (p, key, out)
    return (None,None,None)

def get_xor_permutations(buf):
    out = []
    for key in range(1,255):
        out.append(single_byte_xor(buf, key))
    return out

def four_byte_xor(buf, key):
    out = ''
    for i in range(0,len(buf)/4):
        c = struct.unpack("=I", buf[(i*4):(i*4)+4])[0]
        c ^= key
        out += struct.pack("=I", c)
    return out

def rolling_xor(buf, key):
    out = ''
    k = 0
    for i in buf:
        if k == len(key):
            k = 0
        out += chr(ord(i) ^ ord(key[k]))
        k += 1
    return out

def yaratize(rule, vals):
    n = 0
    strs = []
    for val in vals:
        s = '    $_%d = { ' % n
        for c in val:
            s += "%2.2x " % ord(c)
        s += '}'
        strs.append(s)
        n += 1
    return """
rule %s
{
    strings:
%s

    condition:
    any of them
}""" % (rule,'\n'.join(strs))


