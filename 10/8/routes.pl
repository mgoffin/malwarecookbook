#-----------------------------------------------------------
# routes.pl plug-in for RegRipper (http://regripper.net)
# MHL 2010
#-----------------------------------------------------------
package routes;
use strict;

my %config = (hive          => "System",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20100809);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of PersistentRoutes value";	
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching routes v.".$VERSION);
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'ControlSet001\\Services\\Tcpip\\Parameters\\PersistentRoutes';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("PersistentRoutes");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		foreach my $v (@vals) {
			my $name = $v->get_name();
			my @f = split(/,/, $name);
			::rptMsg("$f[0] mask $f[1] gateway $f[2] metric $f[3]");
		}
	}
	else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
}
1;