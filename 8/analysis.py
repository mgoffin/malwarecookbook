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
# 1) Requires Python >= 2.6 because it uses subprocess.terminate()
#--------------------------------------------------------------------
import os, sys, time
import hashlib
from commands import getoutput 
import shutil, subprocess
import glob

# -----------------------------------------------------------------------

# on windows this is 'C:\\Program Files\\Wireshark\\tshark.exe'
tshark = '/usr/bin/tshark' 
inetsim = '/data/inetsim/inetsim'
python =  '/usr/bin/python'
volatility = '/auto/volatility/volatility'

# -----------------------------------------------------------------------

class Volatility:
    def __init__(self, mem_file):
        '''
        mem_file:  path to the memory dump to analyze
        '''
        self.mem_file = mem_file

    def run_cmd(self, cmd, args=[]):
        '''
        Execute a Volatility command with optional arguments
        '''
        pargs = [python, volatility, cmd, '-f', self.mem_file]
        if len(args):
            pargs.extend(args)
        proc = subprocess.Popen(pargs, stdout=subprocess.PIPE)
        return proc.communicate()[0]

    def pslist(self):
        return self.run_cmd('pslist')
        
    def sockets(self):
        return self.run_cmd('sockets')
        
    def conns(self):
        return self.run_cmd('connections')
        
    def malfind(self, rules, outdir='.tmp'):
        args = ['-d', outdir]
        if os.path.isfile(rules):
            args.extend(['-y', rules])
        return self.run_cmd('malfind2', args)
        
    def hooks(self, outdir='.tmp'):
        args = ['-d', outdir]
        return self.run_cmd('apihooks', args)
        
# -----------------------------------------------------------------------
        
class INetSim:
    def __init__(self, outdir):
        '''
        outdir:  directory to store logs
        '''
        self.outdir = outdir
        self.proc   = None
        
        if os.name != "posix":
            raise 'InetSim is only available on Posix systems'
        if not os.path.isfile(inetsim):
            raise 'Cannot find inetsim in ' + inetsim
        
    def start(self):
        '''
        Start InetSim using the specified output dir
        '''
        self.proc = subprocess.Popen(
            [
                inetsim, 
                '--log-dir', self.outdir, 
                '--report-dir', self.outdir,
            ],
            cwd=os.path.dirname(inetsim),
            stdout=subprocess.PIPE, 
            stdin=subprocess.PIPE
        )
        
    def stop(self):
        '''
        Stop InetSim by sending a SIGTERM
        '''
        if self.proc != None and self.proc.poll() == None:
            self.proc.terminate()
            time.sleep(5)

    def read(self):
        '''
        This reads the InetSim logs and return them
        '''
        outp = ''
        svclog = self.outdir + '/service.log'
        if os.path.isfile(svclog):
            outp += open(svclog).read()
        for f in glob.glob(self.outdir + '/report.*.txt'):
            outp += open(f).read()
        return outp    

# -----------------------------------------------------------------------

class TShark:
    def __init__(self, pcap_file):
        '''
        pcap_file:  path on disk to save the pcap file
        '''
        self.pcap_file = pcap_file
        self.proc = None
       
        if not os.path.isfile(tshark):
            raise 'Cannot find tshark in ' + tshark

    def start(self, iface, guest_ip=None):
        '''
        iface:    interface to capture packets
        guest_ip: set a filter to only capture this host
        '''
        pargs = [tshark, '-p', '-i', iface]
        pargs.extend(['-w', self.pcap_file])
        if guest_ip:
            pargs.extend(['-f', 'host %s' % guest_ip])
        
        self.proc = subprocess.Popen(pargs)
        
    def stop(self):
        if self.proc != None and self.proc.poll() == None:
            self.proc.terminate()
            time.sleep(5)

    def read(self): 
        '''
        Print statistics and details on packet capture 
        '''
        proc = subprocess.Popen(
            [
                tshark, '-z', 'http_req,tree', 
                '-z', 'ip_hosts,tree', '-z', 'io,phs', 
                '-r', self.pcap_file
            ], 
            stdout=subprocess.PIPE
        )
        return proc.communicate()[0]

# -----------------------------------------------------------------------

def nmap(guest_ip, useTcp=True):
    '''
    Scan an IP for open UDP/TCP ports 
    '''
    type = '-sT' if useTcp else '-sU'
    proc = subprocess.Popen(
        [
            'nmap', '-T', 'insane', type, '-p', '0-65535', guest_ip
        ],
        stdout=subprocess.PIPE
    )
    proc.wait()
    return proc.communicate()[0]

def snortscan(pcap_file, onfig, outdir):
    '''
    Scan a packet capture with Snort IDS
    '''
    proc = subprocess.Popen(
        [
            'snort', '-r', pcap_file, 
            '-l', outdir, '-c', config
        ]
    )
    proc.wait()
    alert = outdir + '/alert'
    if os.path.isfile(alert):
        return open(alert).read()
    else:
        return None

