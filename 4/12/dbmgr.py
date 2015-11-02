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
# 1) Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
# 2) This script requires the avsubmit.py module from Chapter 4
# 3) You must NOT use this script if any respective vendors prohibit 
#    you from doing so. See all relevant acceptable usage policies. 
#--------------------------------------------------------------------
import os, sys
from sqlite3 import *
from avsubmit import ThreatExpert
from optparse import OptionParser
import string

DBNAME = "artifacts.db"

class FileSystem:
    def __init__(self, data):
        self.data = data
        self.column_names = {0 : 'ID', 1 : 'Name', 2 : 'Size', 3 : 'Hash', 4 : 'Alias'}

    def process_filenames(self, str):
        files = []
        lines = str.split('<br/>')
        for line in lines:
            line = line.strip()
            line = line.rstrip()
            a_start = line.find('<a href')
            if a_start != -1:
                copy = line[a_start+len('<a href'):]
                f_start = copy.find('>')
                f_end = copy.find('<')
                if f_start != -1 and f_end != -1:
                    files.append("%s%s" % (line[0:a_start], copy[f_start+1:f_end]))
            elif line.lower().startswith('c:'):
                files.append(line)
            elif line.startswith('%'):
                files.append(line)
        return files
        
    def process_hashes(self, str):
        hashes = {}
        lines = str.split('<br/>')
        for line in lines:
            pair = line.split(':')
            hashes[pair[0]] = pair[1].strip()
        return hashes
    
    def process_column(self, column, ncol):
        start_value = column.find('>')
        if start_value == -1:
            return 
            
        column = column[start_value+1:]
    
        end_column = column.find('</td>')
        if end_column == -1:
            return
        
        str = column[0:end_column]
        
        if self.column_names[ncol] == 'Name':
            files = self.process_filenames(str)
            return {'files': files}
        elif self.column_names[ncol] == 'Hash':
            hashes = self.process_hashes(str)
            return {'hashes': hashes}  
            
        return None

    def process_row(self, row):
        end_row = row.find('</tr>')
        if end_row == -1:
            return
            
        row = row[0:end_row]
        offset = 0
        ncol = 0
        
        row_info = {}
        
        while row[offset:].find('<td') != -1:
            ofs = row[offset:].find('<td') + 3
            column = row[offset+ofs:]
            # skip the title column
            info = self.process_column(column, ncol)
            if info != None:
                row_info.update(info)
            offset += ofs
            ncol += 1
            
        return row_info

    def extract(self):
        data = self.data
        table_data = ''
        start_table = data.find('The following files were created in the system')
        if start_table != -1:
            end_table = data[start_table:].find('</table>')
            if end_table != -1: 
                table_data = data[start_table:start_table+end_table]

        offset = 0
        nrow = 0
        file_info = []
        
        while table_data[offset:].find('<tr>') != -1:

            ofs = table_data[offset:].find('<tr>') + 4
            row = table_data[offset+ofs:] 
            if nrow > 0:
                row_info = self.process_row(row)
                file_info.append(row_info)
            offset += ofs
            nrow += 1
        
        return file_info   

class BulletParser:
    def __init__(self, data, mark):
        self.data = data
        self.mark = mark
        
    def parse(self):
        data = self.data
        mark = self.mark
        values = []
        mark = data.find(mark)
        if mark != -1:
            start = data[mark:].find('<ul>')
            if start != -1:
                end  = data[mark+start+4:].find('</ul>')
                if end != -1:
                    data = data[mark+start+4:mark+start+4+end]
                    str = data.split('<li>')
                    for s in str:
                        s = s.rstrip()
                        if s.endswith('</li>'):
                            values.append(s[0:-5])
        
        return values

def bulkimport(page):
    import httplib
    conn = httplib.HTTPConnection('www.threatexpert.com')
    conn.request('GET', '/reports.aspx?page=%d' % page)
    response = conn.getresponse().read()
    lines = response.split('\n')
    for line in lines:
        if line.startswith('<td><a href="report.aspx?md5='):
            addtodb( line[29:61] )

def addtodb(md5):

    if not os.path.isfile(DBNAME):
        print "DB does not exist, try initializing first..."
        return

    conn = connect(DBNAME)
    curs = conn.cursor()
    curs.execute("SELECT id FROM samples WHERE md5=?", (md5,))
    
    row = curs.fetchone()
    if row != None:
        print "Sample already exists in your DB"
        return

    te = ThreatExpert(md5=md5)
    data = te.search_by_hash()
    
    if data == None:
        print "Cannot find file on TE!"
        return
        
    curs.execute("INSERT INTO samples (md5) VALUES (?)", (md5,))
    conn.commit()
    
    sid = curs.lastrowid
    print "Added sample with ID %d" % sid
        
    fs = FileSystem(data)
    file_info = fs.extract()
    
    for info in file_info:
        for file in info['files']:
            if 'MD5' in info['hashes'].keys():
                hash = info['hashes']['MD5'].lower()
                if hash.startswith("0x"):
                    hash = hash[2:]
                curs.execute("INSERT INTO files VALUES (NULL,?,?,?)", (sid, file, hash))
                print " [FILE] %s %s" % (hash, file)
    
    bp = BulletParser(data, 'To mark the presence in the system')
    mutexes = bp.parse()
    
    for mutex in mutexes:
        curs.execute("INSERT INTO mutants VALUES (NULL,?,?)", (sid, mutex))
        print " [MUTEX] " + mutex
    
    bp = BulletParser(data, 'The following Registry Keys')
    regkeys = bp.parse()
    
    for regkey in regkeys:
        ok = True
        for c in regkey:
            if c not in string.printable:
                ok = False
                break
        if ok:
            curs.execute("INSERT INTO regkeys VALUES (NULL,?,?,NULL,NULL)", (sid, regkey))
            print " [REGKEY] " + regkey
    
    conn.commit()
    conn.close()

def delfromdb(md5):
    
    if not os.path.isfile(DBNAME):
        print "DB does not exist!"
        return
    
    conn = connect(DBNAME)
    curs = conn.cursor()
    curs.execute("SELECT id FROM samples WHERE md5=?", (md5,))
    row = curs.fetchone()
    if row == None:
        print "The requested hash is not in your DB"
    else:
        curs.execute("DELETE FROM samples WHERE md5=?", (md5,))
        curs.execute("DELETE FROM files WHERE sid=?", (row[0],))
        curs.execute("DELETE FROM regkeys WHERE sid=?", (row[0],))
        curs.execute("DELETE FROM mutants WHERE sid=?", (row[0],))
        conn.commit()
        
    conn.close()    
    
def showdb():
    
    if not os.path.isfile(DBNAME):
        print "DB does not exist, try initializing first."
        return

    conn = connect(DBNAME)
    conn.text_factory = str
    curs = conn.cursor()
    curs.execute("SELECT * FROM samples")
  
    rows = curs.fetchall()
    
    print "%-6s %s" % ('ID', 'MD5 Hash')
    print "-" * 60

    if rows != None:
        for row in rows:
            print "%-6d %s" % (row[0], row[1])
            curs.execute("SELECT * FROM files WHERE sid=?", (row[0],))
            files = curs.fetchall()
            for file in files:
                print "       [FILE] %s %s" % (file[3], file[2])
            curs.execute("SELECT * FROM regkeys WHERE sid=?", (row[0],))
            regkeys = curs.fetchall()
            for regkey in regkeys:
                print "       [REGKEY] %s" % (regkey[2])
            curs.execute("SELECT * FROM mutants WHERE sid=?", (row[0],))
            mutants = curs.fetchall()
            for mutant in mutants:
                print "       [MUTEX] %s" % (mutant[2])
    else:
        print "Nothing found, try adding samples first."

    conn.close()        

def initdb():

    if os.path.isfile(DBNAME):
        print "File already exists, initialization not required."
        return

    conn = connect(DBNAME)
    curs = conn.cursor()
    
    curs.executescript("""
        CREATE TABLE samples (
            id   INTEGER PRIMARY KEY,
            md5  TEXT
        );
    
        CREATE TABLE files (
            id       INTEGER PRIMARY KEY,
            sid      INTEGER,
            filename TEXT,
            md5      TEXT
        );
    
        CREATE TABLE mutants (
            id   INTEGER PRIMARY KEY,
            sid  INTEGER,
            name TEXT
        );
        
        CREATE TABLE regkeys (
            id        INTEGER PRIMARY KEY,
            sid       INTEGER,
            keyname   TEXT,
            valuename TEXT,
            data      BLOB
        );""")
        
    curs.close()
    
    if os.path.isfile(DBNAME):
        print "Success."
    else:
        print "Failed."

def main():
    parser = OptionParser()
    parser.add_option("-i", "--init", action="store_true",
                       dest="init", default=False, help="initialize DB")
    parser.add_option("-s", "--show", action="store_true",
                       dest="show", default=False, help="show entries in DB")        
    parser.add_option("-a", "--add", action="store",
                       dest="add", type="string", help="add md5 to DB")
    parser.add_option("-d", "--del", action="store",
                       dest="delete", type="string", help="delete md5 from DB")
    parser.add_option("-b", "--bulk", action="store",
                       dest="page", type="int", help="bulk import page")

    (opts, args) = parser.parse_args()
    
    if opts.init:
        initdb()
    elif opts.show:
        showdb()
    elif opts.page != None:
        bulkimport(opts.page)
    elif opts.add != None:
        if opts.add.startswith("0x"):
            opts.add = opts.add[2:]
        addtodb(opts.add)
    elif opts.delete != None:
        if opts.delete.startswith("0x"):
            opts.delete = opts.delete[2:]
        delfromdb(opts.delete)
    else:
        parser.print_help()
        
    print

if __name__ == '__main__':
    main()


    
