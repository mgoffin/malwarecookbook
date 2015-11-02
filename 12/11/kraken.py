import immlib
import getopt
from string import atoi

def main (args):
    imm = immlib.Debugger()
    table = imm.createTable('Kraken Domains', ['Index', 'Name'])
    dga_start = None

    try:
        opts, argo = getopt.getopt(args, "s:")
    except getopt.GetoptError:
        return "Usage: !kraken -s STARTADDR"

    for o,a in opts:
        if o == "-s":
            dga_start = atoi(a, 16)

    if dga_start==None:
        return "Usage: !kraken -s STARTADDR"

    func = imm.getFunction(dga_start)

    imm.setBreakpoint(func.getEnd()[0]) # bp on the end 
    pbuf = imm.remoteVirtualAlloc(4)    # for the output

    for idx in range(0,100):
        if idx % 2: continue # skip odds
        # set EIP to the function's start
        imm.setReg("EIP", dga_start)
        # ESP+4 is the 1st argument and ESP+8 is the 2nd
        imm.writeLong(imm.getRegs()['ESP']+4, pbuf)
        imm.writeLong(imm.getRegs()['ESP']+8, idx)
        # run until we hit a bp (the DGA function's end)
        imm.Run()
        # read the domain from the output buffer
        host = imm.readString(imm.readLong(pbuf))
        table.add('', ['%d' % idx, '%s' % host])

    return "Done generating %d domains" % idx
