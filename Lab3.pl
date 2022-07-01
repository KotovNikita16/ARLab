use strict;
use warnings;

my %top_ip = ();

open(my $in,  "<",  "access.log")  or die "Can't open input.txt: $!";

my $hex = 0;
my $webdav = 0;
my $not_post_get = 0;
while (my $line = <$in>) {
	if($line =~ m/(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/)
	{
		if (exists $top_ip{$&}) {
			$top_ip{$&}++;
		} else {
			$top_ip{$&} = 1;
		}
	}
	
	#suspicious requests
	if ($line =~ m/.+("PROPFIND \/webdav\/)|("WEBDAV.+)/)
	{
		$webdav++;
		print $line;
	} elsif ($line !~ m/.+(http|https):\/\/trgo-demo\.example\.com.+/){
		
		if ($line !~ m/^(.+)\BAppleWebKit\/.+/)
		{
			if ($line =~ m/.+".*\\(x([0-9A-Z]){2}?.+\\)*x([0-9A-Z]){2}.+"/) {
				print $line;
				$hex++;
			}
		}
	}
	if ($line !~ m/.+"GET|POST.+/) {
		print $line;
		$not_post_get++;
	}
}
print "\nSUS requests above\n\n";
print "\nWEBDAV requests: $webdav\n";
print "\nNot POST/GET requests: $not_post_get\n";
print "\nHex requests: $hex\n\n";
print "TOP-10 ip:\n\n";

my $ind = 0;
foreach my $ip (sort {$top_ip{$b} <=> $top_ip{$a}} keys %top_ip) {
    if ($ind < 10)
	{
		print $ind + 1, ") ", $ip, ":\t", $top_ip{$ip}, "\n";
	}
	$ind++;
}
