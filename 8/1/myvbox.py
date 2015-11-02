#!/usr/bin/python
# Copyright (C) 2010 Michael Ligh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# [NOTES] -----------------------------------------------------------
# 1) Tested on Linux (Ubuntu 10.4), Windows 7, and Mac OS X
#--------------------------------------------------------------------
from vmauto import VBoxAuto
import os, sys, time, shutil

'''
path to shared folder on your host machine where you'll
place malware to be picked up by the guest. this folder
should be shared with read-only permissions 

Linux:    vbox_hostpath = '/home/mike/vbox'
Mac OS X: vbox_hostpath = '/Users/mike/Desktop/vbox'
Windows:  vbox_hostpath = 'C:\\Users\\mike\\Desktop\\vbox'
'''
vbox_hostpath = '/Users/mike/Desktop/vbox'

# path to shared folder on your guest machine. this will 
# always be in the form \\vboxsvr\YOURSHARENAME
vbox_guestpath = '\\\\vboxsvr\\input'

def main(argv):
    if len(sys.argv) != 2:
        print 'Usage: %s <file>' % argv[0]
        return 0

    # select your VM to work with
    vm = VBoxAuto('WinXP')
    
    if not vm.check():
        print 'Error initializing'
        sys.exit()
        
    file = sys.argv[1]
        
    # copy the malware to the shared folder
    try:
        shutil.copy(file, vbox_hostpath)
    except Exception, e:
        print 'Cannot copy: %s' % e
        return
        
    try:
        # revert the VM to a clean state
        vm.stop()
        vm.revert('cleanimg')
        # start the VM 
        vm.start()
        
        # do pre-execution analysis here 
        
        # execute malware in the VM using the account 'hal'
        vm.winexec(
            'hal', 
            'password', 
            ["%s\\%s" % (vbox_guestpath, os.path.basename(file))]
            )
            
        # do post-execution analysis here 
        
    except Exception, e:
        print e
        return

if __name__ == '__main__':
    main(sys.argv)
