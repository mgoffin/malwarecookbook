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
# 2) This script is meant to run on a live Windows system
#--------------------------------------------------------------------
import os, sys
from sqlite3 import *
from optparse import OptionParser
import hashlib

try:
    import win32api, win32con, win32event
except ImportError:
    print 'pywin32 is not installed, see http://sourceforge.net/projects/pywin32/'
    sys.exit()

DBNAME = "artifacts.db"

def normalize_path(file):
    file = win32api.ExpandEnvironmentStrings(file)
    if file.startswith("%System%"):
        file = file.replace("%System%", win32api.GetSystemDirectory())
    elif file.startswith("%DesktopDir%"):
        desktop = win32api.ExpandEnvironmentStrings("%UserProfile%")
        desktop = desktop + os.path.sep + 'Desktop'
        file = file.replace("%DesktopDir%", desktop)
    elif file.startswith("%Programs%"):
        progs = win32api.ExpandEnvironmentStrings("%UserProfile%")
        progs = progs + os.path.sep + 'Start Menu' + os.path.sep + 'Programs'
        file = file.replace("%Programs%", progs)
    return file

def normalize_key(regkey):
    hkey_list = {
        win32con.HKEY_LOCAL_MACHINE : 'HKEY_LOCAL_MACHINE',
        win32con.HKEY_CLASSES_ROOT : 'HKEY_CLASSES_ROOT',
        win32con.HKEY_CURRENT_CONFIG : 'HKEY_CURRENT_CONFIG',
        win32con.HKEY_CURRENT_USER : 'HKEY_CURRENT_USER',
        win32con.HKEY_USERS : 'HKEY_USERS'}
    for hkey in hkey_list:
        if regkey.startswith(hkey_list[hkey]):
            return (hkey, regkey[len(hkey_list[hkey])+1:])
    return None, None

def check_files(curs, sample, strict):
    curs.execute("SELECT * FROM files WHERE sid=?", (sample[0],))
    files = curs.fetchall()
    for file in files:
        path = normalize_path(file[2])
        if os.path.isfile(path):
            if strict:
                data = open(path, 'rb').read()
                md5 = hashlib.md5(data).hexdigest()
                if md5.lower() == file[3].lower():
                    print "Found strict match %s (infection by %s)" % (path, sample[1])
            else:
                print "[File] loose match %s\n [REF] http://www.threatexpert.com/report.aspx?md5=%s" % (path, sample[1])

def check_regkeys(curs, sample):
    curs.execute("SELECT * FROM regkeys WHERE sid=?", (sample[0],))
    regkeys = curs.fetchall()
    for regkey in regkeys:
        (hkey, subkey) = normalize_key(regkey[2])
        try:
            handle = win32api.RegOpenKey(hkey, subkey)
        except:
            continue
        print "[Regkey] %s\n [REF] http://www.threatexpert.com/report.aspx?md5=%s" % (subkey, sample[1])

def check_mutants(curs, sample):
    curs.execute("SELECT * FROM mutants WHERE sid=?", (sample[0],))
    mutants = curs.fetchall()
    for mutant in mutants:
        try:
            handle = win32event.OpenMutex(win32con.READ_CONTROL, 0, mutant[2])
        except:
            continue
        print "[Mutex] %s\n [REF] http://www.threatexpert.com/report.aspx?md5=%s" % (mutant[2], sample[1])

def main():
    parser = OptionParser()
    parser.add_option("-f", "--files",
                action="store_true", dest="files",
                default=False, help="check files")
    parser.add_option("-s", "--strict",
                action="store_true", dest="strict",
                default=False, help="use strict mode (check hash) for files")
    parser.add_option("-r", "--regkeys",
                action="store_true", dest="regkeys",
                default=False, help="check registry")
    parser.add_option("-m", "--mutants",
                action="store_true", dest="mutants",
                default=False, help="check mutexes")

    (opts, args) = parser.parse_args()

    if not os.path.isfile(DBNAME):
        print "Cannot find " + DBNAME
        sys.exit()

    if not opts.files and not opts.regkeys and not opts.mutants:
        parser.print_help()
        parser.error("You must tell me to do something.")

    conn = connect(DBNAME)
    conn.text_factory = str
    curs = conn.cursor()
    curs.execute("SELECT * FROM samples")
    samples = curs.fetchall()

    print "Found %d samples in database" % (len(samples))

    for sample in samples:
        if opts.files:
            check_files(curs, sample, opts.strict)
        if opts.regkeys:
            check_regkeys(curs, sample)
        if opts.mutants:
            check_mutants(curs, sample)

    conn.close()

if __name__ == '__main__':
    main()