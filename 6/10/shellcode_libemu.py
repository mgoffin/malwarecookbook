#!/usr/bin/python
import re,sys,libemu

if len(sys.argv) <= 1:
	print 'Use this script with %s path_to_shellcode_file' % (sys.argv[0])
for file in sys.argv[1:]:
	fin = open(file,'rb')
	data = fin.read()
	fin.close()
	
	emu = libemu.Emulator()
	result = emu.run_shellcode(data)
