#!/usr/bin/python
import pefile
import sys, os

IMAGE_FILE_DLL = 0x2000

if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
    print "\nUsage: dll2exe.py <filename> [AddressOfEntryPoint RVA (hex)]\n"
    sys.exit()
else:
    FileName = sys.argv[1]

pe = pefile.PE(FileName)
OldChars = pe.FILE_HEADER.Characteristics
NewChars = OldChars - (OldChars & IMAGE_FILE_DLL)
pe.FILE_HEADER.Characteristics = NewChars

print "\nConverting %s from DLL to EXE" % FileName
print "Characteristics 0x%x => 0x%x" % (OldChars, NewChars)

if len(sys.argv) == 3:
    OldEntryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    NewEntryPoint = int(sys.argv[2], 16)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = NewEntryPoint
    print "Entry point RVA 0x%x => 0x%x" % (OldEntryPoint, NewEntryPoint)

ExeFileName = FileName + ".exe"
pe.write(ExeFileName)

print "Saved new file as %s\n" % ExeFileName

