#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h> //For errno - the error number


int main()
{ 

    int sendsock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);

	int one = 1;
	const int *val = &one;
	
	if (setsockopt (sendsock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

    return 0;
}