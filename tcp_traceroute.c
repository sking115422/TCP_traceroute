#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h> //For errno - the error number



int checkStringIsNumeric (char *str)
{
    int count = 0;
    printf("strlen: %ld\n", strlen(str));
    int i;
    for (i = 0;i< strlen(str); i++)
    {
        printf("char: %c\n", str [i]);
        if (isdigit(str[i]) > 0)
        {
            count++;
            printf("count: %d\n", count);
        }
    }

    if (count == strlen(str))
        return 1;
    else 
        return 0;
}




int main(int argc, char **argv) 
{
   
    int option_val = 0;

    char * MAX_HOPS = "30";
    char * DST_PORT = "80";
    char * TARGET = "google.com";

    while((option_val = getopt(argc, argv, "m:p:t:h")) != -1)
    {
        switch(option_val)
        {
            case 'm':
                MAX_HOPS = optarg; 
                break;
            case 'p':
                DST_PORT = optarg;
                break;
            case 't':
                TARGET = optarg;
                break;
            case 'h':
                printf("-h  Show this help message and exit\n");
                printf("-m  Max hops to probe (default = 30)\n");
                printf("-p  TCP destination port (default = 80)\n");
                printf("-t  Target domain or IP\n");
                exit(0);
        }
    }

    //Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create socket");
		exit(1);
	}

    //IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;

    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		exit(0);
	}

	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 4096);
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	
	//some address resolution
	strcpy(source_ip , "192.168.1.2");
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr ("1.2.3.4");
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;

    //Send the packet
    if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        perror("sendto failed");
    }
    //Data send successfully
    else
    {
        printf ("Packet Send. Length : %d \n" , iph->tot_len);
    }
    // sleep for 1 seconds
    sleep(1);


    printf("done...");
}



//////MAIN    
    
// int conn = openRawConnection(TARGET, atoi(DST_PORT));

/////HELPER METHOD

// int openRawConnection(char *TARGET, int portnum)
// {
//     struct hostent *he;
//     struct in_addr **addr_list;
//     struct in_addr addr;

//     char target_copy [strlen(TARGET)];

//     strcpy(target_copy, TARGET);

//     char * first_str = strtok(target_copy, ".");

//     printf("target: %s\n", TARGET);

//     char *first_ip;
//     if (checkStringIsNumeric (first_str) == 0)
//     {
//         he = gethostbyname(TARGET);
//         if (he == NULL) { 
//             herror("gethostbyname"); 
//             exit(0);
//         }

//         printf("\nDNS INFO\n");
//         printf("Official name is: %s\n", he->h_name);
//         char *temp = inet_ntoa(*(struct in_addr*)he->h_addr);
//         strcpy(first_ip, temp);
//         printf("IP address: %s\n", first_ip);
//         printf("All addresses: ");
//         addr_list = (struct in_addr **)he->h_addr_list;
//         for(int i = 0; addr_list[i] != NULL; i++) {
//             printf("%s ", inet_ntoa(*addr_list[i]));
//         }
//         printf("\n");

//     }
//     else 
//     {
//         first_ip = TARGET;
//     }

//     int raw_tcp_socket;

//     //creating socket
//     raw_tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

//     struct sockaddr_in remote_address;

//     remote_address.sin_family = AF_INET;
//     remote_address.sin_port = htons(portnum);
//     inet_aton(first_ip, &remote_address.sin_addr);

    
//     //establishing TCP connection
//     if ( connect(raw_tcp_socket, (struct sockaddr *) &remote_address, sizeof(remote_address)) != 0 )
//     {
//         close(raw_tcp_socket);
//         perror("Error");
//         exit(0);
//     }

//     printf("\nNew raw TCP socket created!\n");

//     return raw_tcp_socket;
// }
