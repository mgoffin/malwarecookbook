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
# 1) Tested on Linux (Ubuntu) 
#--------------------------------------------------------------------
from vmauto import VMwareAuto
import os, sys, time, analysis
import hashlib, shutil
from avsubmit import VirusTotal
from pescanner import PEScanner

# path to where report data will be stored
# the directory must exist, but a subdirectory
# will be created with the md5 of your malware sample
#report_path = '/data/reports'
report_path = "/auto/reports"

# name of the clean snapshot 
snapname = 'cleanimg'

# credentials for the user account on the guest VM
# that you will use to execute malware 
user = 'Administrator'
passwd = 'password'

# ip address for the guest (assuming you know it
# and its static. used to scan with nmap 
guest_ip = '192.168.1.99'

# path to your vmware guest's VMX configuration file
guest_vmx = '/auto/MalwareAnalysis/WinXP.vmx'

def printhdr(name):
    print '#' * 75
    print '# ' + name
    print '#' * 75
    
def analyze(vm, sample, rdir, inetsim):
    '''
    vm:      a VMwareAuto object
    sample:  path to malware sample to analyze
    rdir:    report directory
    '''
    
    # scan the sample with our PEScanner module
    printhdr('Submission Details')
    pescan = PEScanner([sample])
    pescan.collect()

    # submit the sample to VT and print results
    printhdr('Antivirus Results')
    vt = VirusTotal(sample)
    detects = vt.submit()
    for key,val in detects.items():
        print "  %s => %s" % (key, val)

    # revert the VM to its clean snapshot 
    vm.revert(snapname)
    vm.start()
    time.sleep(15)
    
    # set the credentials for tasks in the guest VM
    vm.setuser(user, passwd)

    # copy the malware sample to the VM's hard drive
    dst = 'C:\\%s' % os.path.basename(sample)
    vm.copytovm(sample, dst)

    # start a packet capture on the host
    pcap = analysis.TShark(rdir + '/file.pcap')
    pcap.start('eth0', guest_ip)
    
    # start INetSim for simulated Internet. Comment  
    # out these lines to allow the malware sample
    if inetsim:
        inet = analysis.INetSim(rdir)
        inet.start()

    # execute the malware in the guest VM, let it run 
    # for one minute 
    vm.winexec(dst)
    time.sleep(60)
    
    # take a screen shot of the guest VM's desktop
    vm.scrshot(rdir + '/shot.bmp')
    
    # suspend the VM 
    vm.suspend()
    
    # stop INetSim and print the captured logfiles 
    if inetsim:
        inet.stop()
        logs = inet.read()
        if len(logs):
            printhdr('Inetsim Logs')
            print logs

    # stop TShark and print the traffic statistics 
    printhdr('Network Traffic')
    pcap.stop()
    print pcap.read()
    
    printhdr('Memory Analysis')
    vol = analysis.Volatility(vm.findmem())
    print vol.pslist()
    print vol.conns()
    print vol.sockets()
    print vol.hooks()
    print vol.malfind('/data/yara.rules', rdir + '/mal')

def main(argv):
    if len(sys.argv) < 2:
        print 'Usage: %s <file> [--inetsim]' % argv[0]
        return 0

    if sys.argv[len(sys.argv)-1] == "--inetsim":
        inetsim = True
    else:
        inetsim = False
        
    vm = VMwareAuto(guest_vmx)

    if os.path.isfile(sys.argv[1]):
        rdir = report_path + \
               os.path.sep + \
               hashlib.md5(open(sys.argv[1]).read()).hexdigest()

        try:
            os.mkdir(rdir)
        except:
            pass

        analyze(vm, sys.argv[1], rdir, inetsim)
    else:
        return 1

if __name__ == '__main__':
    main(sys.argv)
