#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent; # We'll use this library for HTTP requests
use Socket qw(inet_aton PF_INET SOCK_STREAM sockaddr_in);

# Get the target host and port from the command line arguments
my ($target_host, $target_port) = @ARGV;

# Validate input
unless ($target_host && $target_port) {
    die "Usage: $0 <target_host> <target_port>\n";
}

# Validate the target port
unless ($target_port =~ /^\d+$/ && $target_port > 0 && $target_port <= 65535) {
    die "Invalid target port: $target_port\n";
}

# Perform the scan
if (is_port_open($target_host, $target_port)) {
    print "Port $target_port is open on $target_host\n";
    check_exploitdb($target_host, $target_port);
} else {
    print "Port $target_port is closed on $target_host\n";
}

sub is_port_open {
    my ($host, $port) = @_;
    my $proto = getprotobyname('tcp');
    my $iaddr = inet_aton($host);
    my $paddr = sockaddr_in($port, $iaddr);
    
    socket(SOCKET, PF_INET, SOCK_STREAM, $proto);
    
    # Set a timeout for the connection attempt (in seconds)
    my $timeout = 3;
    eval {
        local $SIG{ALRM} = sub { die "Timeout\n" };
        alarm $timeout;
        connect(SOCKET, $paddr);
        alarm 0;
    };
    
    if ($@ && $@ =~ /Timeout/) {
        return 0;  # Port is closed
    }
    
    close SOCKET;
    return 1;  # Port is open
}

sub check_exploitdb {
    my ($host, $port) = @_;
    
    my $search_url = "https://www.exploit-db.com/search?q=$host+$port";
    my $ua = LWP::UserAgent->new;
    
    my $response = $ua->get($search_url);
    
    if ($response->is_success) {
        my $content = $response->decoded_content;
        
        if ($content =~ /No results/i) {
            print "No known exploits found in ExploitDB for $host:$port\n";
        } else {
            print "Potential exploits found in ExploitDB for $host:$port\n";
        }
    } else {
        print "Error fetching ExploitDB search results: " . $response->status_line . "\n";
    }
}