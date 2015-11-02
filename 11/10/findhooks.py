import immlib

def isExternalToModule(imm, addr, dest):
    '''is an address within range of a DLL'''
    mod = imm.getModulebyAddress(addr)
    if (dest < mod.getBaseAddress()) or \
       (dest > mod.getBaseAddress()+mod.getSize()):
        return True
    return False

def main(args):
    imm = immlib.Debugger()
    table = imm.createTable('Rootkit Locator',\
        ['Function', 'Address', 'Opcode'])
    # this allows us to enumerate all exports from all
    # DLLs loaded in the process. we could alternately
    # walk the LDR_MODULE list and use pefile to parse
    # the PE header and find all exports
    sym = imm.getAllSymbols()
    # for each loaded DLL
    for modname in sym.keys():
        modsym = sym[modname]
        # for each symbol in the DLL
        for modaddr in modsym.keys():
            mod = modsym[modaddr]
            string = modname.split(".")[0] + "." + mod.name
            # this works like GetProcAddress. if it succeeds,
            # then we've found a valid export symbol
            addr = imm.getAddress(string)
            if addr == -1:
                continue
            # disassemble the function's 1st instruction
            op = imm.disasm(addr)
            instr = op.getDisasm()
            # check for the most typical types of inline hooks
            if op.isJmp() or op.isCall():
                dest = op.getJmpAddr()
                if isExternalToModule(imm, addr, dest):
                    table.add('', ['%s' % string,\
                        '0x%x' % addr, '%s' % instr])
            # check for hooks of type "push 0x????????; retn"
            elif op.isPush():
                nextop = imm.disasm(addr + op.getSize())
                if nextop.isRet():
                    call_dest = imm.readLong(addr+op.getSize()+1)
                    if isExternalToModule(imm, addr, call_dest):
                        table.add('', ['%s' % string,\
                             '0x%x' % addr, '%s' % instr])