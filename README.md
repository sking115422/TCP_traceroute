# TCP_TRACEROUTE

## TCP version of traceroute

This program emulates the standard implimentation of traceroute in Linux, however, instead of sending and recieving UDP packets we use TCP packets.

This program is only runable on Linux based OSs. It uses structs that will only compile on a linux machine. More information on this can be found here:

* https://sites.uclouvain.be/SystInfo/usr/include/netinet/tcp.h.html
* https://github.com/afabbro/netinet/blob/master/ip.h
* https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip_icmp.h.html

One thing I included that is different than the traditional traceroute is that it will print to console if an ICMP packet returned is coming from the target destination. This was an anomally I found while testing my program so I decided to include it as flag that prints to console. 

## How to Run

Can be run from the command line with the following arguments:

$ ./tcp_traceroute.py -h 

usage: tcp_traceroute.py [-m MAX_HOPS] [-p DST_PORT] -t TARGET

Run to start a tcp_traceroute session

Optional arguments:
* -h, --help   show this help message and exit
* -m   MAX_HOPS  Max hops to probe (default = 30)
* -p   DST_PORT  TCP destination port (default = 80)
* -t   TARGET    Target domain or IP (default = google.com)

## Example Command Line Syntax

sudo ./tcp_traceroute -t example.com 