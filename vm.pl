#!/usr/bin/perl
use strict;
use warnings;
use Term::ANSIColor;
use LWP::UserAgent; # We'll use this library for HTTP requests
use Socket qw(inet_aton PF_INET SOCK_STREAM sockaddr_in);

sub main_menu {
        print colored(['bold rainbow'], << "BANNER");
**************************************************************
*                        VulnMaX                             *
*                         v:0.02                             *
*              Welcome to VulnMaX Main Menu                  *
*                     Made by Hissing                        *
**************************************************************
BANNER

    print "Select an option:\n";
    print "1. Port Scanning\n";
    print "2. Network Mapping and Enumeration\n";
    print "3. Exit\n";

    my $choice = <STDIN>;
    chomp $choice;

    if ($choice == 1) {
        port_scanning();
    } elsif ($choice == 2) {
        network_mapping();
    } elsif ($choice == 3) {
        exit;
    } else {
        print "Invalid choice. Please try again.\n";
        main_menu();
    }
}

sub port_scanning {
    print "Enter the target host: ";
    my $target_host = <STDIN>;
    chomp $target_host;

    print "Enter the target port: ";
    my $target_port = <STDIN>;
    chomp $target_port;

    unless ($target_host && $target_port) {
        die "Usage: $0 <target_host> <target_port>\n";
    }

    unless ($target_port =~ /^\d+$/ && $target_port > 0 && $target_port <= 65535) {
        die "Invalid target port: $target_port\n";
    }

    if (is_port_open($target_host, $target_port)) {
        print "Port $target_port is open on $target_host\n";
        check_exploitdb($target_host, $target_port);
    } else {
        print "Port $target_port is closed on $target_host\n";
    }
}

sub is_port_open {
    my ($host, $port) = @_;

    my $proto = getprotobyname('tcp');
    my $iaddr = inet_aton($host);
    my $paddr = sockaddr_in($port, $iaddr);

    socket(SOCKET, PF_INET, SOCK_STREAM, $proto);

    my $timeout = 3;  # Set a timeout for the connection attempt (in seconds)
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
            # You might want to display or log the search results here
            # Depending on the ExploitDB website structure, you may need to parse the content to extract relevant information
        }
    } else {
        print "Error fetching ExploitDB search results: " . $response->status_line . "\n";
    }
}


sub network_mapping {
    print "Enter the base IP address (e.g., 192.168.1): ";
    my $base_ip = <STDIN>;
    chomp $base_ip;

    unless ($base_ip) {
        die "Usage: $0 <base_ip>\n";
    }

    for my $last_octet (1..254) {
        my $target_ip = "$base_ip.$last_octet";
        if (is_host_alive($target_ip)) {
            print "Host $target_ip is alive\n";
            perform_port_scan($target_ip);
        }
    }
    main_menu();  # After completing this section, return to the main menu
}

sub perform_port_scan {
    my ($host) = @_;

    for my $port (1..65535) {
        if (is_port_open($host, $port)) {
            print "Port $port is open on $host\n";
            grab_banner($host, $port);
        }
    }
}

sub grab_banner {
    my ($host, $port) = @_;

    my $proto = getprotobyname('tcp');
    my $iaddr = inet_aton($host);
    my $paddr = sockaddr_in($port, $iaddr);

    socket(SOCKET, PF_INET, SOCK_STREAM, $proto);

    my $timeout = 3;  # Set a timeout for the connection attempt (in seconds)
    eval {
        local $SIG{ALRM} = sub { die "Timeout\n" };
        alarm $timeout;
        connect(SOCKET, $paddr);
        alarm 0;
    };

    if (!$@) {
        my $banner = <SOCKET>;
        chomp $banner;
        print "Banner for $host:$port: $banner\n";
    }

    close SOCKET;
}

# Start the program by displaying the main menu
main_menu();
