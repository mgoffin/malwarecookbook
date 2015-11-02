import immlib
import getopt
from string import atoi

def main (args):
    imm = immlib.Debugger()
    base = None
    size = None
	
    try:
        opts, argo = getopt.getopt(args, "b:s:")
    except getopt.GetoptError:
        return "Usage: !rebase -b BASE -s SIZE"

    for o,a in opts:
        if o == "-b":
            base = atoi(a, 16)
        elif o == "-s":
            size = atoi(a, 16)

    if base==None or size==None:
        return "Usage: !rebase -b BASE -s SIZE"
		
    # pointer to PEB_LDR_DATA
    ldr = imm.readLong(imm.getPEBaddress()+12)
    # pointer to InLoadOrder list
    load_order_list = imm.readLong(ldr+12)
    # pointer to the first loaded module's base and size
    # this will be to the exe image itself 
    ptr_base = load_order_list+24
    ptr_size = load_order_list+32
    mod_base = imm.readLong(ptr_base)
    # overwrite the base and size with the values 
    # supplied by the user 
    imm.writeLong(ptr_base, base)
    imm.writeLong(ptr_size, size)
