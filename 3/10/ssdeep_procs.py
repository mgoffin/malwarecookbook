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
# 1) Tested on Windows XP and Windows 7
# 2) This program is meant to run on a live Windows system
# 3) pywin32 is required and ssdeep.exe must be in your PATH
#--------------------------------------------------------------------
import os, sys
import subprocess
from ctypes import *
from ctypes.wintypes import *

try:
    import win32process, win32con, win32security, win32api
except ImportError:
    print 'pywin32 is not installed, see http://sourceforge.net/projects/pywin32/'
    sys.exit()

# this threshold is the minimum percent similarity between the file on disk
# and the the executable in memory for the script to trigger a warning
# 80% is a reasonable number, most windows applications are 85%+
threshold = 80

OpenProcess = windll.kernel32.OpenProcess
ReadProcessMemory = windll.kernel32.ReadProcessMemory
CloseHandle = windll.kernel32.CloseHandle
CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
Module32First = windll.kernel32.Module32First
Module32Next = windll.kernel32.Module32Next
CloseHandle = windll.kernel32.CloseHandle

TH32CS_SNAPMODULE32 = 0x00000008
class MODULEENTRY32(Structure):
     _fields_ = [("dwSize", c_ulong),
                 ("th32ModuleID", c_ulong),
                 ("th32ProcessID", c_ulong),
                 ("GlblcntUsage", c_ulong),
                 ("ProccntUsage", c_ulong),
                 ("modBaseAddr", c_ulong),
                 ("modBaseSize", c_ulong),
                 ("hModule", c_ulong),
                 ("szModule", c_char * 256),
                 ("szExePath", c_char * 260)]

def get_proc_params(pid):
    base = size = path = None
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, pid)
    me32 = MODULEENTRY32()
    me32.dwSize = sizeof(MODULEENTRY32)
    if Module32First(hModuleSnap, byref(me32)) == win32con.FALSE:
        return (base, size, path)
    while True:
        if me32.szModule.endswith(".exe"):
            base = me32.modBaseAddr
            size = me32.modBaseSize
            path = me32.szExePath
            break
        if Module32Next(hModuleSnap, byref(me32)) == win32con.FALSE:
            break
    CloseHandle(hModuleSnap)
    return (base, size, path)

def enable_debug():
    flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
    hToken = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        flags)
    priv_id = win32security.LookupPrivilegeValue(
        None,
        win32security.SE_DEBUG_NAME)
    old_privs = win32security.AdjustTokenPrivileges(
        hToken,
        0,
        [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])

def dump_process(pid, base, size):
    dmp_file = "proc.%d.exe" % pid
    try:
        hProc = OpenProcess(
            win32con.PROCESS_VM_READ,
            0,
            pid)

        if hProc == None:
            return

        buf = (c_ubyte * size)()
        cread = c_ulong(0)

        if ReadProcessMemory(hProc, base, \
            byref(buf), size, byref(cread)):
            FILE = open(dmp_file, "wb")
            FILE.write(buf)
            FILE.close()
    finally:
        CloseHandle(hProc)

    if os.path.isfile(dmp_file) and os.path.getsize(dmp_file) > 0:
        return dmp_file

    return None

def compare_hash(disk_file, mem_file):
    os.popen("ssdeep -b \"%s\" > hash.txt" % disk_file)
    res = os.popen("ssdeep -bm hash.txt -a \"%s\"" % mem_file)
    for line in res.readlines():
        if 'matches' in line:
            line = line[line.rfind("(")+1:]
            line = line[:line.find(")")]
            return int(line)
    return 0

def main():
    enable_debug()

    pids = win32process.EnumProcesses()
    print "%-24s %-6s %-6s" % ("Process", "Pid", "Matched")

    for pid in pids:
        (base, size, path) = get_proc_params(pid)
        if not base or not size or not path:
            continue

        if path.startswith("\\??\\"):
            path = path[4:]
        elif path.startswith("\\SystemRoot"):
            path = path.replace("\\SystemRoot", win32api.GetWindowsDirectory())

        if not os.path.isfile(path):
            continue

        dmp_file = dump_process(pid, base, size)

        if not dmp_file or not os.path.isfile(dmp_file):
            continue

        flag = ''
        percent = compare_hash(path, dmp_file)
        if percent <= threshold:
            flag = 'possible packed exe'
        print "%-24s %-6d %-2s%% %-24s" % (os.path.basename(path), pid, percent, flag)

if __name__ == '__main__':
    main()

