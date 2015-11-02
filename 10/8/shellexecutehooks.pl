#-----------------------------------------------------------
# shellexecutehooks.pl plugin for RegRipper (http://regripper.net)
# MHL 2010
#-----------------------------------------------------------
package shellexecutehooks;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20100809);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of ShellExecuteHooks value";	
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub getclsid {
    my $root_key = shift;
    my $name = shift;
    my $clsid_path = "Classes\\CLSID\\".$name;
    my $clsid; 
    if ($clsid = $root_key->get_subkey($clsid_path)) {
        my $mod  = $clsid->get_subkey("InProcServer32")->get_value("")->get_data();
        my $default = $clsid->get_value("");
        my $desc = "{empty}";
        if ($default) { 
            $desc = $default->get_data();
        }
        ::rptMsg("Description: $desc");
		::rptMsg("Module: $mod");
    } else { 
        ::rptMsg($clsid_path." not found.");
        ::rptMsg("");
    }
}

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching shellexecutehooks v.".$VERSION);
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
	    ::rptMsg("ShellExecuteHooks");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
	    my @vals = $key->get_list_of_values();
		foreach my $v (@vals) {
		    my $name = $v->get_name();
		    my $data = $v->get_data();
		    $data = "{empty}" if $data eq "";
		    ::rptMsg("$name: $data");
		    getclsid($root_key, $name);
		    ::rptMsg("");
		}
    } else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
}
1;