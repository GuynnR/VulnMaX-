# VulnMaX Perl Script

![Rainbow Banner](rainbow_banner.png)

VulnMaX is a Perl script for performing basic port scanning, network mapping, and enumeration. It utilizes Term::ANSIColor for colorful terminal output and LWP::UserAgent for making HTTP requests.

## Features

- **Port Scanning**: Check if a specific port is open on a target host.
- **Network Mapping and Enumeration**: Perform port scanning for a range of IP addresses.
- **ExploitDB Integration**: Search ExploitDB for known exploits related to a target.
- **Colorful Rainbow Banner**: A visually appealing and colorful banner at the main menu.

## Prerequisites

- Perl installed on your system.
- Required Perl modules: `Term::ANSIColor`, `LWP::UserAgent`, `Socket`.

## Usage

1. Clone or download the script to your local machine.
2. Open a terminal and navigate to the script's directory.
3. Run the script using the command:

   ```shell
   perl vulnmax.pl
