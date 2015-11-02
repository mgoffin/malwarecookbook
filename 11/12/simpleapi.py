from winappdbg import Debug, EventHandler
import sys
import os

class MyEventHandler( EventHandler ):

    # Add the APIs you want to hook
    apiHooks = {

        'kernel32.dll' : [
                         ( 'CreateFileW'  ,   7  ),
                         ],
        }
   
    # The pre_ functions are called upon entering the API
    
    def pre_CreateFileW(self, event, ra, lpFileName, dwDesiredAccess,
             dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                                dwFlagsAndAttributes, hTemplateFile):
        
        fname = event.get_process().peek_string(lpFileName, fUnicode=True)
        print "CreateFileW: %s" % (fname)
   
    # The post_ functions are called upon exiting the API
    
    def post_CreateFileW(self, event, retval):
        if retval:
            print 'Suceeded (handle value: %x)' % (retval)
        else:
            print 'Failed!'

if __name__ == "__main__":

    if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
        print "\nUsage: %s <File to monitor> [arg1, arg2, ...]\n" % sys.argv[0]
        sys.exit()

    # Instance a Debug object, passing it the MyEventHandler instance
    debug = Debug( MyEventHandler() )

    try:
        # Start a new process for debugging
        p = debug.execv(sys.argv[1:], bFollow=True)

        # Wait for the debugged process to finish
        debug.loop()

    # Stop the debugger
    finally:
        debug.stop()

