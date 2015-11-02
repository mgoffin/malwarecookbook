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
# 2) You should redirect the output of this program to an HTML file
# 3) If the map doesn't render in Firefox, try Internet Explorer 
#--------------------------------------------------------------------
import os,sys
from optparse import OptionParser

try:
    from pygeoip import GeoIP
except ImportError:
    print 'pygeoip is not installed, see http://code.google.com/p/pygeoip/'
    sys.exit()

__PATH_TO_DATABASE__ = 'GeoLiteCity.dat'

__GEO_HEADER__ = """<html><head>
<script type="text/javascript" src="http://www.google.com/jsapi"></script>
<script type="text/javascript">
    google.load('visualization', '1', {packages: ['geomap']});
</script>
<script type="text/javascript">
    function drawVisualization() {
    // Create and populate the data table.
    var data = new google.visualization.DataTable();
    data.addColumn('string', '', 'Country');
    data.addColumn('number', 'Hosts');"""

__GEO_FOOTER__ = """
    var geomap = new google.visualization.GeoMap(document.getElementById('geo_map'));
    geomap.draw(data, null);
    }
    google.setOnLoadCallback(drawVisualization);
</script>
</head>
<body>
<div id="geo_map" style="width: 600px; height: 350px;"></div>
</body>
</html>"""

def output_geo(gi, ip_list):
    print __GEO_HEADER__

    countries = {}
    
    for ip in ip_list:
        try:
            rec = gi.record_by_addr(ip)
        except:
            continue
        if rec == None:
            continue
        if 'country_code' not in rec.keys():
            continue
        if rec['country_code'] in countries.keys():
            countries[rec['country_code']] += 1
        else:
            countries[rec['country_code']] = 1
    
    print "    data.addRows(%d);" % (len(countries))
        
    c = 0
    for country, value in countries.items():
        print "    data.setValue(%d, 0, '%s');" % (c, country)
        print "    data.setValue(%d, 1, %d);" % (c, value)
        c += 1
   
    print __GEO_FOOTER__

if __name__=='__main__':
    parser = OptionParser()
    parser.add_option("-f", "--file", action="store", dest="filename", 
        type="string", help="filename with CRLF-separated IPs")
    parser.add_option("-a", "--addr", action="store", dest="addr",
        type="string", help="CSV list of IPs")

    (opts, args) = parser.parse_args()
    
    if opts.filename != None:
        ip_list = open(opts.filename).readlines()
    elif opts.addr != None:
        ip_list = opts.addr.split(',')
    else:
        parser.print_help()
        parser.error("You must supply a list of IPs or file with IPs!")

    gi = GeoIP(__PATH_TO_DATABASE__)
    output_geo(gi, ip_list)
        
    
    