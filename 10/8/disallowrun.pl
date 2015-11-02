#-----------------------------------------------------------
# disallowrun.pl plug-in for RegRipper (http://regripper.net)
# MHL 2010
#-----------------------------------------------------------
package disallowrun;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20100809);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of DisallowRun value";	
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching disallowrun v.".$VERSION);
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

    my $enabled = "0";

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
	    my @vals = $key->get_list_of_values();
		loop: foreach my $v (@vals) {
		    my $name = $v->get_name();;
		    if ($name eq "DisallowRun") { 
		        $enabled = $v->get_data();
		        last loop;
		    }
		}
    }
	
	if ($enabled ne "1") { 
	    print "DisallowRun is not Enabled!\n";
	    return;
	}
	
	$key_path .= '\\DisallowRun';
	
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("DisallowRun");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		foreach my $v (@vals) {
			my $name = $v->get_name();
			my $data  = $v->get_data();
			print "$name => $data\n";
		}
	}
	else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
}
1;