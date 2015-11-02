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
use strict;
use warnings;
use File::Basename;
use Getopt::Long;
use Parse::Win32Registry qw(:REG_);

binmode(STDOUT, ':utf8');

Getopt::Long::Configure('bundling');

GetOptions('all|a'      => \my $all,
           'ca|c'       => \my $ca,
           'root|r'     => \my $root,
           'my|m'       => \my $my);

my $filename = shift or die usage();
my $pattern  = shift;
my $outdir   = "certs";

my $registry = Parse::Win32Registry->new($filename)
    or die "'$filename' is not a registry file\n";
my $root_key = $registry->get_root_key
    or die "Could not get root key of '$filename'\n";
    
sub dumpcerts { 
    my $root_key = shift;
    my $key_path = shift;
    # dump the certs to a subdirectory named according to the
    # subkey of the registry in which the cert is stored 
    my @subkeys = split('\\\\', $key_path);
    my $dir_path = "$outdir/".$subkeys[2];
	my $sep = "=" x 75 . "\n";
	if (my $key = $root_key->get_subkey($key_path)) {
        foreach my $subkey ($key->get_list_of_subkeys) {
            # get the certificate's raw binary data
            my $data = $subkey->get_value("Blob")->get_data;
            next if (!defined($data));
            # look for the DER header using this regex
            if ($data =~ m/(\x30[\x81-\x82][\x00-\x05]{1}[\x00-\xFF]+)/) { 
                my $len = length($1);
                mkdir $dir_path, 0777 unless -d $dir_path;
                my $fname = "$dir_path/".$subkey->get_name;
                # write the DER certificate to a file 
                open(CERT, ">$fname") or next;
                print CERT $1;
                close(CERT);
                # allow the user to filter output by CN or subject
                my $subject = `openssl x509 -in $fname -inform DER -subject -noout`;
                if (!defined($pattern) or $subject =~ m/$pattern/i) { 
                    print $sep;
                    print "Wrote $len bytes to $fname\n";
                    print "LastWrite Time ".gmtime($subkey->get_timestamp())." (UTC)\n";
                    print $sep;
                    # convert the DER certificate to PEM format 
                    print `openssl x509 -inform DER -in $fname -outform PEM -out $fname`;
                    # verify the certificate with a known good CA list
                    print `openssl verify -CAfile ca-certificates.crt $fname`;
                    # print details about the certificate 
                    print `openssl x509 -inform PEM -in $fname -noout -text`;
                }
            } 
        }
    }
}

mkdir $outdir, 0777 unless -d $outdir;

if ($all or $ca) { 
    dumpcerts($root_key, 'Microsoft\\SystemCertificates\\CA\\Certificates');
}
if ($all or $root) { 
    dumpcerts($root_key, 'Microsoft\\SystemCertificates\\ROOT\\Certificates');
}
if ($all or $my) { 
    dumpcerts($root_key, 'Microsoft\\SystemCertificates\\MY\\Certificates'); 
}

if ($all) { 
    dumpcerts($root_key, 'Microsoft\\SystemCertificates\\AuthRoot\\Certificates');
    dumpcerts($root_key, 'Microsoft\\SystemCertificates\\Disallowed\\Certificates'); 
    dumpcerts($root_key, 'Microsoft\\SystemCertificates\\trust\\Certificates'); 
    dumpcerts($root_key, 'Microsoft\\SystemCertificates\\TrustedPublisher\\Certificates'); 
}
    
sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

Dumps and prints details about installed PKI certificates.

$script_name <filename> [subject] [-a] [-c] [-r] [-m]
    -a or --all       dump all certs listed below and also:
                           AuthRoot (non Microsoft root CA certs)
                           Disallowed (rejected/untrustworthy)
                           trust certs (enterprise trust certs)
                           TrustedPublisher (certs explicitly accepted)
    -c or --ca        dump CA (intermediate CA certs)
    -r or --root      dump ROOT (trusted root CA certs)
    -m or --my        dump MY (user's personal certs)
USAGE
}