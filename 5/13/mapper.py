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
# 2) For more information, see:
#    * http://matplotlib.sourceforge.net/mpl_toolkits.basemap.basemap.html
#    * http://matplotlib.sourceforge.net/basemap/doc/html/users/intro.html
#    * http://www.packtpub.com/article/plotting-geographical-data-using-basemap
#--------------------------------------------------------------------
from optparse import OptionParser
import sys

try:
    import matplotlib
    matplotlib.use("Agg") # overrides DISPLAY req for SSH 
    import matplotlib.pyplot as plt
except ImportError:
    print 'python-matplotlib is not installed, cannot continue!'
    sys.exit()
    
try:
    import numpy as np
except ImportError:
    print 'python-numpy is not installed, cannot continue!'
    sys.exit()

try:
    from mpl_toolkits.basemap import Basemap
except ImportError:
    print 'basemap is not installed, see http://sourceforge.net/projects/matplotlib/files/matplotlib-toolkits/'
    sys.exit()

try:
    from pygeoip import *
except ImportError:
    print 'pygeoip is not installed, see http://code.google.com/p/pygeoip/'
    sys.exit()
    
__PATH_TO_DATABASE__ = 'GeoLiteCity.dat'
    
class Mapper:
    def __init__(self, ip_list):
        self.ip_list = ip_list
        
    def map(self, title="", output="map.png", quiet=True, showcity=True, type="mill"):
            
        gi = GeoIP(__PATH_TO_DATABASE__)
        
        if gi == None:
            print "Cannot find %s!" % __PATH_TO_DATABASE__
            return
    
        cities = []
        lat = []
        lon = []
        
        for ip in self.ip_list:
            rec = gi.record_by_addr(ip)
            if rec == None:
                continue
            if not quiet: print rec
            
            # if the city isn't available, use the region/state
            # if the region/state isn't available, use the country
 
            if 'city' not in rec.keys():
                if 'region_name' not in rec.keys():
                    if 'country_name' not in rec.keys():
                        locid = 'n/a'
                    else:
                        locid = rec['country_name']
                else:
                    locid = rec['region_name']
            else:
                locid = rec['city']
                
            cities.append(locid)
            lat.append(rec['latitude'])
            lon.append(rec['longitude'])
    
        if type == "ortho":
            # Orthographic projection 
            m = Basemap(projection='ortho', lat_0=45, lon_0=10)
        elif type == "mill":
            # Miller Cylindrical projection
            m = Basemap(projection='mill',
                llcrnrlon=-180. ,llcrnrlat=-60,
                urcrnrlon=180. ,urcrnrlat=80.)
        elif type == "robin":
            # Robinson projection 
            m = Basemap(projection='robin', lon_0=0, resolution='c')
        else:
            print "Unsupported projection type!"
            return 
        
        m.drawmapboundary()
        m.drawcoastlines()
        m.fillcontinents()
        
        # map city coordinates to map coordinates
        x, y = m(lon, lat)
        
        # draw a red dot at cities coordinates
        plt.plot(x, y, 'ro')

        if showcity:
            for city, xc, yc in zip(cities, x, y):
              plt.text(xc+250000, yc-150000, city, fontsize=8,
                bbox=dict(facecolor='yellow', alpha=0.5)) 
        
        plt.title(title)
        plt.savefig(output)

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
        
    m = Mapper(ip_list)
    m.map(title="Test Image", output="map.png", type="mill")
    
    print "Done."
    