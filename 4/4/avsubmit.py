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
# 2) You must NOT use this script if the respective vendors begin to
#    prohibit doing so in the future. You must consult all relevant 
#    acceptible usage policies.
#--------------------------------------------------------------------
import urllib, urllib2
import sys
import httplib
import os
import re
import time
import hashlib
import urlparse
from optparse import OptionParser

try:
    from sqlite3 import *
except ImportError:
    print "Cannot import sqlite3, the database function is disabled."

# This should be stock with Python2.6 but not supplied in Python2.5
try:
    import simplejson
except ImportError:
    print 'You must install simplejson for VirusTotal, see http://www.undefined.org/python/'
            
DBNAME  = "virus.db"
MAXWAIT = (60*10) # ten minutes 

# You must fill this in for VirusTotal (see http://www.virustotal.com/advanced.html)
VTAPIKEY=''

class Jotti:
    def __init__(self, file):
        self.file = file
        
        f = open(self.file, "rb")
        self.content = f.read()
        f.close()
        
        self.headers = {
            'User-Agent' : 'Jotti Uploader 0.0.1',
            'Accept' : '*/*',
        }
        
        self.cookie = ''
        self.apc = ''
        
    def parse_response(self, results):
        
        detects = {}

        while results.find('scannerid') != -1:
            offset = results.find('scannerid')
            results = results[offset+12:]
            vendor = results[0:results.find('\"')]
            if vendor == '':
                continue
            offset = results.find('virusname')
            if offset == -1:
                continue
            results = results[offset+12:]
            virus = results[0:results.find('\"')]
            if virus == '':
                continue
            detects[vendor] = virus.replace('\\', '')
            
        return detects
        
    def get_detects(self, analysis_url):
        
        detects = {}
        tries = 0
        
        print "Trying to get results for the next %d seconds..." % MAXWAIT
        
        while tries < 10:
        
            print "Try %d" % tries
            
            netloc = urlparse.urlparse(analysis_url)[1]
            path   = urlparse.urlparse(analysis_url)[2]
        
            try:
                conn = httplib.HTTPConnection(netloc)
                conn.request('GET', path, None, self.headers)
                results = conn.getresponse().read()
            except Exception, e:
                print "Error parsing response: %s" % e
                break
                
            if results.find('scanid:') != -1:
                scanid = results[results.find('scanid:')+9:]
                scanid = scanid[0:scanid.find('\"')]
                
                if scanid == '':
                    tries += 1
                    time.sleep(MAXWAIT/10)
                    continue
                    
                #print "Initialized scanid: %s" % scanid
                results = None
                
                try:
                    conn = httplib.HTTPConnection(netloc)
                    results_url = '/nestor/getscanprogress.php?' + self.cookie + '&lang=en&scanid=' + scanid
                    conn.request('GET', results_url)
                    results = conn.getresponse().read()
                except Exception, e:
                    print "Error querying progress: %s" % e
                    break
                
                if results != None:
                    detects = self.parse_response(results)
                    if (detects != None) and (len(detects) > 0):
                        break
            
            tries += 1
            time.sleep(MAXWAIT/10)
        
        return detects
        
    def submit(self):
    
        analysis_url = self.search_by_hash()
        
        if analysis_url == None:
            analysis_url = self.upload_file()
            if analysis_url != None:
                print "You can find the new analysis here: %s" % analysis_url 
                return self.get_detects(analysis_url)
        elif analysis_url != "nosubmit":
            print "You can find the existing analysis here: %s" % analysis_url
            return self.get_detects(analysis_url)

        return {}
        
    def search_by_hash(self):
    
        if self.cookie == '' or self.apc == '':
            self.get_params()

        print "Initialized session cookie: %s" % self.cookie
        print "Initialized APC: %s" % self.apc

        md5 = hashlib.md5(self.content).hexdigest().upper()

        print "Checking Jotti's databse for file with MD5: %s" % md5
        response = ''
        
        try:
            conn = httplib.HTTPConnection('virusscan.jotti.org')
            query_url = '/nestor/getfileforhash.php?' + self.cookie + "&hash=" + md5 + "&output=json"
            conn.request('GET', query_url)
            response = conn.getresponse().read()

            if response.find('FILE_NOT_FOUND') != -1:
                print "The file does not already exist on Jotti..."
                return None
                
            if response.find('HASH_INVALID') != -1:
                print "The hash format is invalid..."
                return None

            if response.startswith('false'):
                print "The file exists, but analysis is incomplete (try again later)..."
                return "nosubmit"
                
            response = response.replace('\"', '')
            return 'http://virusscan.jotti.org/en/scanresult/' + response 
        except Exception, e:
            print "Error searching for hash: %s" % e
            pass
        
        return None
        
    def get_params(self):
        
        try:
            conn = httplib.HTTPConnection('virusscan.jotti.org')
            conn.request('GET', '/en')
            response = conn.getresponse()
            headers = response.getheader('set-cookie')
            if headers.find('sessionid') == 0:
                self.cookie = headers[0:headers.find(';')]
            body = response.read()
            var = body.find('APC_UPLOAD_PROGRESS')
            if var != -1:
                value = body[var:].find("value=")
                if value != -1:
                    body = body[var+value+7:]
                    self.apc = body[0:body.find('\"')]
        except Exception, e:
            print "Error getting parameters: %s" % e
            return 

    def upload_file(self):
    
        if self.cookie == '' or self.apc == '':
            self.get_params()
            
        print "Attempting to upload the sample, please wait..."
        
        my_headers = self.headers
        my_headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------7da29022600d6'
        my_headers['Cookie'] = "%s; lang=en" % self.cookie
        
        body = "-----------------------------7da29022600d6\r\n"
        body += "Content-Disposition: form-data; name=\"APC_UPLOAD_PROGRESS\"\r\n\r\n"
        body += "%s\r\n" % self.apc
        body += "-----------------------------7da29022600d6\r\n"
        body += "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n"
        body += "15728640\r\n"
        body += "-----------------------------7da29022600d6\r\n"
        body += "Content-Disposition: form-data; name=\"scanfile\"; "
        body += "filename=\"%s\"\r\n" % os.path.basename(self.file)
        body += "Content-Type: application/octet-stream\r\n"
        body += "\r\n"
        body += self.content
        body += "\r\n"
        body += "-----------------------------7da29022600d6--\r\n"
        
        try:
            conn = httplib.HTTPConnection('virusscan.jotti.org')
            conn.request('POST', '/processupload.php', body, my_headers)
            response = conn.getresponse().read()
            offset = response.find('top.location.href=')
            #print response
            if offset != -1:
                response = response[offset+19:]
                response = response[0:response.find('\"')]
                return 'http://virusscan.jotti.org' + response 
        except Exception, e:
            print "Error uploading file: %s" % e
            pass
            
        return None

class ThreatExpert:
    def __init__(self, file=None, md5=None):
    
        self.md5 = md5
    
        if file != None:
            data = open(file, "rb").read()
            self.md5 = hashlib.md5(data).hexdigest().lower()

    def get_data_between(self, data, start_tag, end_tag):
        start = data.find(start_tag)
        if start != -1:
            start += len(start_tag)
            end = data[start:].find(end_tag)
            if end != -1:
                return data[start:start+end]
        return None
                
    def remove_html_tags(self, data):
        p = re.compile(r'<.*?>')
        return p.sub('', data)

    def split_record(self, text):
        parts = text.split(" ", 1)
        vendor = parts[1].replace("[", "")
        vendor = vendor.replace("]", "")
        detect = parts[0]
        return (vendor, detect)

    def parse_response(self, response):
        
        detects = {}
        
        # handle multiple aliases (viruses only)
        buf1 = self.get_data_between(response, "<li>Alias:</li>", "</ul>")
        # handle multiple aliases (viruses and packers)
        buf2 = self.get_data_between(response, "<li>Alias &amp; packer info:</li>", "</ul>")
        
        if buf1 != None:
            aliases = re.findall("<li>.+</li>", buf1)
            
            for alias in aliases:
                text = self.remove_html_tags(alias)
                vendor, detect = self.split_record(text)
                detects[vendor] = detect
        elif buf2 != None:
            aliases = re.findall("<li>.+</li>", buf2)
            
            for alias in aliases:
                text = self.remove_html_tags(alias)
                vendor, detect = self.split_record(text)
                detects[vendor] = detect
        else:
            # handle single aliases (only 1 av result)
            if response.find("<li>Alias: ") != -1:
                buf = response[response.find("<li>Alias: ")+11:]
                if buf.find("</li>") != -1:
                    text = buf[:buf.find("</li>")]
                    vendor, detect = self.split_record(text)
                    detects[vendor] = detect
                
        return detects

    def search_by_hash(self):

        search_url = 'http://www.threatexpert.com/report.aspx?md5=' + self.md5

        print "Checking ThreatExpert for file with MD5: %s" % self.md5
        
        try:
            conn = httplib.HTTPConnection('www.threatexpert.com')
            conn.request('GET', '/report.aspx?md5=' + self.md5)
            response = conn.getresponse().read()
            if response.find('Submission Summary') != -1:
                print "Analysis exists: %s" % search_url
                return response
            else:
                print "Analysis does not yet exist!"
        except Exception, e:
            print "Error searching for hash: %s" % e
            pass
            
        return 
        
    def submit(self):
        
        detects = {}
        response = self.search_by_hash()
        if response != None:
            detects = self.parse_response(response)
        
        return detects

class NoVirusThanks:
    def __init__(self, file):
        self.file = file
        
        f = open(self.file, "rb")
        self.content = f.read()
        f.close()
        
        self.headers = {
            'User-Agent' : 'NoVirusThanks Uploader 0.0.1',
            'Accept' : '*/*',
        }
        
    def get_data_between(self, data, start_tag, end_tag):
        start = data.find(start_tag)
        if start != -1:
            start += len(start_tag)
            end = data[start:].find(end_tag)
            if end != -1:
                return data[start:start+end]
        return None
        
    def remove_html_tags(self, data):
        p = re.compile(r'<.*?>')
        return p.sub(' ', data)
        
    def parse_response(self, location):
    
        detects = {}
        location = location.replace("file", "analysis")
        print location
        tries = 0
        
        while tries < 10:
        
            print "Try %d" % tries
            
            netloc = urlparse.urlparse(location)[1]
            path   = urlparse.urlparse(location)[2]
        
            try:
                conn = httplib.HTTPConnection(netloc)
                conn.request('GET', path, None, self.headers)
                results = conn.getresponse().read()
            except Exception, e:
                print "Error parsing response: %s" % e
                break
                
            if results.find("Error: No report found") != -1:
                tries += 1
                time.sleep(MAXWAIT/10)
                continue
                
            buf = self.get_data_between(results, '<!-- Virus information table -->', '</table>')
            if buf != None:
                buf = self.get_data_between(buf, '<tbody>', '</tbody>')
                if buf != None:
                    rows = buf.split("<tr>")
                    for row in rows:
                        text = self.remove_html_tags(row)
                        cols = text.split("  ")
                        vendor = cols[0].strip()
                        if vendor == "":
                            continue
                        try:
                            detect = cols[3].strip()
                        except:
                            continue
                        if detect == "" or detect == "-":
                            continue
                        detects[vendor] = detect
            break
            
        return detects
        
    def upload_file(self):
        
        print "Submitting file to NoVirusThanks, please wait..."
        
        my_headers = self.headers
        my_headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------47972514120'
        
        body = "-----------------------------47972514120\r\n"
        body += "Content-Disposition: form-data; name=\"upfile\"; "
        body += "filename=\"%s\"\r\n" % os.path.basename(self.file)
        body += "Content-Type: application/octet-stream\r\n"
        body += "\r\n"
        body += self.content
        body += "\r\n"
        body += "-----------------------------47972514120\r\n"
        body += "Content-Disposition: form-data; name=\"submitfile\"\r\n"
        body += "\r\n"
        body += "Submit File\r\n"
        body += "-----------------------------47972514120--\r\n"
        
        try:
            conn = httplib.HTTPConnection('vscan.novirusthanks.org')
            conn.request('POST', '/', body, my_headers)
            response = conn.getresponse()
            location = response.getheader('location')
        except Exception, e:
            print "Error uploading file: %s" % e
            return None
        
        return location
        
    def submit(self):
        detects = {}
        location = self.upload_file()
        if location != None:
            detects = self.parse_response(location)
        return detects
        
## {{{ http://code.activestate.com/recipes/146306/ (r1)
import httplib, mimetypes

def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()
    return h.file.read()

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
## end of http://code.activestate.com/recipes/146306/ }}}

class VirusTotal:
    def __init__(self, file):
        self.file = file
        
        f = open(self.file, "rb")
        self.content = f.read()
        f.close()

    def check(self, res):
        url = "https://www.virustotal.com/api/get_file_report.json"
        parameters = {"resource": res, 
                      "key": VTAPIKEY}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        response_dict = simplejson.loads(json)
        try:
            return response_dict.get("report")[1]
        except:
            return {}

    def upload_file(self):
        host = "www.virustotal.com"
        selector = "http://www.virustotal.com/api/scan_file.json"
        fields = [("key", VTAPIKEY)]
        file_to_send = self.content
        files = [("file", os.path.basename(self.file), file_to_send)]
        return post_multipart(host, selector, fields, files)

    def submit(self):
        resource = hashlib.md5(self.content).hexdigest()
        detects = self.check(resource)
        if len(detects) > 0:
            print 'File already exists on VirusTotal!'
            return detects
        print 'File does not exist on VirusTotal, uploading...'
        json = self.upload_file()
        if json.find("scan_id") != -1:
            offset = json.find("scan_id") + len("scan_id") + 4
            scan_id = json[offset:]
            scan_id = scan_id[:scan_id.find("\"")]
            print 'Trying scan_id %s for %d seconds' % (scan_id, MAXWAIT)
            i = 0
            while i<(MAXWAIT/10):
                detects = self.check(scan_id)
                if len(detects) > 0:
                    return detects
                time.sleep(MAXWAIT/10)
                i += 1
        return {}

def savetodb(filename, detects, force):
    
    if len(detects) == 0:
        print "Nothing to add, submission failed."
        return
    
    if not os.path.isfile(DBNAME):
        print "%s does not exist, try initialization first." % DBNAME
        return
        
    conn = connect(DBNAME)
    curs = conn.cursor()
    
    md5 = hashlib.md5(open(filename, 'rb').read()).hexdigest()
    
    curs.execute("SELECT id FROM samples WHERE md5=?", (md5,))
    ids = curs.fetchall()
   
    if len(ids):
        if not force:
            ids = ["%d" % id[0] for id in ids]
            print "The sample exists in virus.db with ID %s" % (','.join(ids))
            print "Use the -o or --overwrite option to force"
            return
        else:
            curs.execute("DELETE FROM samples WHERE md5=?", (md5,))

    try:
        curs.execute("INSERT INTO samples VALUES (NULL,?)", (md5,))
    except Exception, e:
        print "Error inserting record: %s" % e
        print "Is your virus.db in a writable path?"
        return
        
    sid = curs.lastrowid 
    print "Added sample to database with ID %d" % sid
    for key,val in detects.items():
        curs.execute("INSERT INTO detects VALUES (NULL,?,?,?)", (sid, key, val))
    
    conn.commit()
    curs.close()

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
    
        CREATE TABLE detects (
            id       INTEGER PRIMARY KEY,
            sid      INTEGER,
            vendor   TEXT,
            name     TEXT
        );
        """)
        
    curs.close()
    
    if os.path.isfile(DBNAME):
        print "Success."
    else:
        print "Failed."

def main():
    parser = OptionParser()
    parser.add_option("-i", "--init", action="store_true", 
                       dest="init", default=False, help="initialize virus.db")
    parser.add_option("-o", "--overwrite", action="store_true",
                       dest="force", default=False,
                      help="overwrite existing DB entry")
    parser.add_option("-f", "--file", action="store", dest="filename",
                      type="string", help="upload FILENAME")
    parser.add_option("-v", "--virustotal", action="store_true",
                       dest="virustotal", default=False,
                      help="use VirusTotal")
    parser.add_option("-e", "--threatexpert", action="store_true",
                       dest="threatexpert", default=False,
                      help="use ThreatExpert")
    parser.add_option("-j", "--jotti", action="store_true",
                       dest="jotti", default=False,
                      help="use Jotti")
    parser.add_option("-n", "--novirus", action="store_true",
                       dest="novirus", default=False,
                      help="use NoVirusThanks")
    
    (opts, args) = parser.parse_args()
    
    if opts.init:
        initdb()
        sys.exit()
    
    if opts.filename == None:
        parser.print_help()
        parser.error("You must supply a filename!")
    if not opts.virustotal and not opts.threatexpert and not opts.jotti and not opts.novirus:
        parser.print_help()
        parser.error("You must supply an action!")

    if not os.path.isfile(opts.filename):
        parser.error("%s does not exist" % opts.filename)

    if opts.virustotal:
        print "Using VirusTotal..."
        if not sys.modules.has_key("simplejson"):
            print 'You must install simplejson'
            sys.exit()
        vt = VirusTotal(opts.filename)
        detects = vt.submit()
        for key,val in detects.items():
            print "  %s => %s" % (key, val)
        savetodb(opts.filename, detects, opts.force)
        print 
        
    if opts.jotti:
        print "Using Jotti..."
        jotti = Jotti(opts.filename)
        detects = jotti.submit()
        for key,val in detects.items():
            print "  %s => %s" % (key, val)
        savetodb(opts.filename, detects, opts.force)
        print 
        
    if opts.threatexpert:
        print "Using ThreatExpert..."
        te = ThreatExpert(opts.filename)
        detects = te.submit()
        for key,val in detects.items():
            print "  %s => %s" % (key, val)
        savetodb(opts.filename, detects, opts.force)
        print 
        
    if opts.novirus:
        print "Using NoVirusThanks..."
        nvt = NoVirusThanks(opts.filename)
        detects = nvt.submit()
        for key,val in detects.items():
            print "  %s => %s" % (key, val)
        
if __name__ == '__main__':
    main()
