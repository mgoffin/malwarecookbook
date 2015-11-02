#!/usr/bin/python
import sys, yara, commands

rules = yara.compile(sys.argv[1])
data  = open(sys.argv[2], 'rb').read()

matches = rules.match(data=data)

isupx = [m for m in matches if m.rule.startswith("UPX")]

if isupx:
    outp = commands.getoutput("upx -d %s" % sys.argv[2])
    print outp