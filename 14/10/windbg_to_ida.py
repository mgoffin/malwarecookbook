import sys, os

def usage(s):
    print "Usage: %s <file>" % s
    sys.exit()

if len(sys.argv) != 2: 
    usage(sys.argv[0])
    
filename = sys.argv[1]

if not os.path.isfile(filename):
    usage(sys.argv[0])

lines = open(filename).readlines()

for line in lines:
    try:
        parts = line.strip().split()
        addr  = parts[0]
        name  = parts[2]
        name  = name.split("!")[1]
        print "MakeName(0x%x, \"%s\");" % (int(addr, 16), name)
    except:
        print "Invalid line: %s" % line