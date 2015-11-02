import immlib
import getopt, string
import immutils
import os

def usage(imm):
    imm.Log("Usage: !scd -f FILETOCHECK")

def checkop(op):
    instr = op.getDisasm()
    junk = ["IN", "OUT", "LES", "FSUBR", "DAA",
            "BOUND", "???", "AAM", "STD", "FIDIVR",
            "FCMOVNE", "FADD", "LAHF", "SAHF", "CMC",
            "FILD", "WAIT", "RETF", "SBB", "ADC",
            "IRETD", "LOCK", "POP SS", "POP DS", "HLT",
            "LEAVE", "ARPL", "AAS", "LDS", "SALC",
            "FTST", "FIST", "PADD", "CALL FAR", "FSTP",
            "AAA", "FIADD"]
    for j in junk:
        if instr.startswith(j):
            return False
    if op.isCall() or op.isJmp():
        if op.getJmpAddr() > 0x7FFFFFFF:
            return False
    return True

def main (args):
    imm     = immlib.Debugger()
    scfile  = None
    conditional = False

    try:
        opts, argo = getopt.getopt(args, "f:")
    except getopt.GetoptError:
        usage(imm)
        return

    for o,a in opts:
        if o == "-f":
            try:
                scfile = a
            except ValueError, msg:
                return "Invalid argument: %s" % a

    if scfile == None or not os.path.isfile(scfile):
        usage(imm)
        return

    # Get something going so the context is valid
    imm.openProcess("c:\\windows\\system32\\notepad.exe")

    # Read file contents
    buf = open(scfile, "rb").read()
    cb  = len(buf)

    # Copy the contents to process memory
    mem = imm.remoteVirtualAlloc(cb)
    imm.writeMemory(mem, buf)

    # Clarify the start and end of the buffer
    start = mem
    end   = mem + cb

    table = imm.createTable('Shell Code Detect',\
        ['Ofs', 'Abs', 'Op', 'Op2', 'Op3'])

    while start < end:
        # Disassemble the instruction
        d = imm.disasm(start)
        c = d.getSize()
        # Skip anything that isn't a jump/call
        if (not d.isCall()) and (not d.isJmp()):
            start += c
            continue
        # Get the destination address of the jump/call
        dest = d.getJmpAddr()
        # The destination must land within the shell code
        # buffer or else we've just located a false positive
        if dest < start or dest > end:
            start += c
            continue
        # Disassemble the first 3 ops at destination
        op2 = imm.disasm(dest)
        op3 = imm.disasm(dest+op2.getSize())
        op4 = imm.disasm(dest+op2.getSize()+op3.getSize())
        # Use a simple validity check to reduce fp's
        if checkop(op2) and checkop(op3) and checkop(op4):
            table.add('', ['0x%x' % (start - mem),\
            '0x%x' % start,\
            '%s' % d.getDisasm(),\
            '%s' % op2.getDisasm(),\
            '%s' % op3.getDisasm()])

        start += c

    return "done"