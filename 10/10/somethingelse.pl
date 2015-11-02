#!/usr/bin/perl
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

eval 'exec /usr/bin/perl  -S $0 ${1+"$@"}'
    if 0; # not running under some shell
use strict;
use warnings;

use Encode;
use File::Basename;
use Getopt::Long;
use Parse::Win32Registry qw(:REG_ hexdump);
use MIME::Base64;
use Regexp::Common qw /net/;
use Regexp::Common qw /URI/;

binmode(STDOUT, ':utf8');

Getopt::Long::Configure('bundling');

GetOptions('all|e'         => \my $all,
           'base64|b'      => \my $base64,
           'pe|p'          => \my $pe,
           'ipaddr|i'      => \my $ipaddr,
           'http|h'        => \my $http,
           'binstr|s'      => \my $binstr);

my $filename = shift or die usage();
#my $rules_file = shift or die usage();

my $registry = Parse::Win32Registry->new($filename)
    or die "'$filename' is not a registry file\n";
my $root_key = $registry->get_root_key
    or die "Could not get root key of '$filename'\n";

traverse($root_key);

sub isbase64 { 
    no warnings;
    my $data = shift;
    my $dlen = length($data);
    if ($dlen < 16 or $dlen % 4 != 0) {
        return undef;
    }
    if ($data =~ m/[\s\x00]/) {
        return undef;
    }
    if ($data =~ m/[0-9a-zA-Z\+\/=]{$dlen}/) {
        my $dec = decode_base64($data);
        $dlen = length($dec);
        if ($dec =~ m/[\x20-\x7f]{$dlen}/) { 
            return $dec;
        }
    }
    return undef;
}

sub ispe { 
    my $data = shift;
    my $dlen = length($data);
    if ($dlen < 1024) { 
        return 0;
    }
    my $dos = substr($data,0,2);
    if ($dos eq 'MZ') { 
        my $ntoff = ord(substr($data,0x3C,4));
        if ($ntoff > 1024) { 
            return 0;
        }
        my $nt = substr($data,$ntoff,2);
        if ($nt eq 'PE') { 
            return 1;
        }
    }
    return 0;
}
      
sub isdotquad { 
    my $data = shift;
    if ($data =~ /^$RE{net}{IPv4}{-keep}$/) { 
        return 1 if ($1 ne "0.0.0.0");
    }
    return 0;
}
      
sub ishttpuri {
    my $data = shift;
    return 1 if ($data =~ /^$RE{URI}{HTTP}/);
    return 0;
}
      
sub isnotsz { 
    my $data = shift;
    my $len  = length($data);
    no warnings;
    return 1 if ($data =~ m/[\x01-0x7F]+\x00/);
    return 0;
}
      
my $cert = 0;
      
sub traverse {
    my $key = shift;
    
    LOOP: foreach my $value ($key->get_list_of_values) {
    
        if (!defined($value->get_data)) { 
            next LOOP;
        }
        
        my $path = $key->get_path;
        my $name = $value->get_name;
        my $type = $value->get_type_as_string;
        
        my $header = "$path\nLastWrite ".gmtime($key->get_timestamp())." (UTC)\n".
                     "Value: $name\nType: $type\n";

        my $data = $value->get_data;
        
        if ($all or $base64) { 
            my $dec = isbase64($data);
            if (defined($dec)) { 
                print $header;
                print "Encoded: $data\nDecoded: $dec\n";
                print "\n";
            }
        }
        
        if (($all or $pe) and ispe($data)) { 
            print $header;
            print "PE file detected!\n";
        }
        
        
        if (($all or $ipaddr) and isdotquad($data)) { 
            if (!($path =~ /version/i) and !($name =~ /version/i)) {
                print $header;
                print "$data\n";
            }
        }
        
        if (($all or $http) and ishttpuri($data)) { 
            print $header;
            print "$data\n";
        }
        
        if ($all or $binstr) { 
            if ($value->get_type == REG_SZ and isnotsz($data)) { 
                print $header;
                print hexdump($value->get_raw_data);
            }
        }

        #open(DATA, ">data.out") or next LOOP;
        #print DATA $data;
        #close(DATA);
        #my $res = `yara -m -s reg.yara data.out`;
        #if ($res ne "") { 
        #   print $res;
        #}

    }

    foreach my $subkey ($key->get_list_of_subkeys) {
        traverse($subkey);
    }
}

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

Dumps and prints details about interesting registry aritfacts.

$script_name <filename> [-a] [-b] [-p] [-i] [-h] [-s]
    -a or --all         dump all (everything below)
    -b or --base64      find base64 encoded strings
    -p or --pe          find pe files (dll/exe/sys)
    -i or --ipaddr      find dot quad ip addresses
    -h or --http        find http urls
    -s or --binstr      find binary data disguised as a string
USAGE
}
