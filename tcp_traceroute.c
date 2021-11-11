#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>
#include <signal.h>

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
    int i;
    for (i = 0;i< strlen(str); i++)
    {
        if (isdigit(str[i]) > 0)
        {
            count++;
        }
    }

    if (count == strlen(str))
        return 1;
    else 
        return 0;
}


char * resolveToIP(char *TARGET, int portnum)
{
    struct hostent *he;
    struct in_addr **addr_list;
    struct in_addr addr;

    char target_copy [strlen(TARGET)];

    strcpy(target_copy, TARGET);

    char * first_str = strtok(target_copy, ".");

    printf("target: %s\n", TARGET);

    char *target_ip;
    if (checkStringIsNumeric (first_str) == 0)
    {
        he = gethostbyname(TARGET);
        if (he == NULL) 
        { 
            herror("gethostbyname"); 
            exit(0);
        }

        printf("\nDNS INFO\n");
        printf("Official name is: %s\n", he->h_name);
        char *temp = inet_ntoa(*(struct in_addr*)he->h_addr);
        strcpy(target_ip, temp);
        printf("IP address: %s\n", target_ip);
        printf("\n");
    }
    else 
    {
        target_ip = TARGET;
    }

    return target_ip;
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}


void timeoutFunc (int signum)
{
    printf("Timeout occured! No ICMP packet received...\n");
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

    int portnum = atoi(DST_PORT);
    char * target_ip = resolveToIP(TARGET, portnum);
    int max_hops = atoi(MAX_HOPS);

    int sendsock = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

    int one = 1;
    const int *val = &one;
    if (setsockopt (sendsock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    int recvsock_icmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    int recvsock_raw = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    
    struct timeval tv;
    tv.tv_sec = 1;  /* 5 Secs Timeout */

    if (setsockopt(recvsock_icmp, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval)) < 0)
    {
        perror("Error setting socket timeout");
        exit(0);
    }
    if (setsockopt(recvsock_raw, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval)) < 0)
    {
        perror("Error setting socket timeout");
        exit(0);
    }

    for (int i = 1; i < max_hops + 1; i++)
    {

        char dg [4096];

        struct ip *iph = (struct ip *) dg;
        struct tcphdr *tcph = (struct tcphdr *) dg + sizeof (struct ip);

        struct sockaddr_in sain;

        sain.sin_family = AF_INET;
        sain.sin_port = htons(portnum);
        sain.sin_addr.s_addr = inet_addr (target_ip);

        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);	/* no payload */
        iph->ip_id = htonl (54321);	/* the value doesn't matter here */
        iph->ip_off = 0;
        iph->ip_ttl = i;
        iph->ip_p = 6;
        iph->ip_sum = 0;		/* set it to 0 before computing the actual checksum later */
        iph->ip_src.s_addr = inet_addr ("127.0.0.1");/* SYN's can be blindly spoofed */
        iph->ip_dst.s_addr = sain.sin_addr.s_addr;
        tcph->th_sport = htons (12345);	/* arbitrary port */
        tcph->th_dport = htons (portnum);
        tcph->th_seq = random ();/* in a SYN packet, the sequence is a random */
        tcph->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
        tcph->th_x2 = 0;
        tcph->th_off = 0;		/* first and only tcp segment */
        tcph->th_flags = TH_SYN;	/* initial connection request */
        tcph->th_win = htonl (65535);	/* maximum allowed window size */
        tcph->th_sum = 0;   /* if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission */
        tcph->th_urp = 0;
        iph->ip_sum = csum ((unsigned short *) dg, iph->ip_len >> 1);


        if (sendto (sendsock, dg, iph->ip_len ,	0, (struct sockaddr *) &sain, sizeof (sain)) < 0)
        {
            perror("sendto failed");
        }

        else
        {
            printf ("Packet Sent. Length : %d \n" , iph->ip_len);
        }

        struct sockaddr saddr;
        int saddr_size = sizeof(saddr);


        unsigned char * buf = (unsigned char *) malloc(65536);
        
        int bytes_recieved = recvfrom(recvsock_icmp, buf, 65536, 0, &saddr, &saddr_size);

        printf("bytes_recieved: %d\n", bytes_recieved);


    }
    



    printf("done...\n");



}


////TEST 1
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // //Create a raw socket
	// int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	
	// if(s == -1)
	// {
	// 	//socket creation failed, may be because of non-root privileges
	// 	perror("Failed to create socket");
	// 	exit(1);
	// }

    // //IP_HDRINCL to tell the kernel that headers are included in the packet
	// int one = 1;
	// const int *val = &one;

    // if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	// {
	// 	perror("Error setting IP_HDRINCL");
	// 	exit(0);
	// }

	// //Datagram to represent the packet
	// char datagram[4096] , source_ip[32] , *data , *pseudogram;
	
	// //zero out the packet buffer
	// memset (datagram, 0, 4096);
	
	// //IP header
	// struct iphdr *iph = (struct iphdr *) datagram;
	
	// //TCP header
	// struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	// struct sockaddr_in sin;
	
	// //Data part
	// data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	// strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	
	// //some address resolution
	// strcpy(source_ip , "127.0.0.1");
	// sin.sin_family = AF_INET;
	// sin.sin_port = htons(80);
	// sin.sin_addr.s_addr = inet_addr ("108.177.122.102");
	
	// //Fill in the IP Header
	// iph->ihl = 5;
	// iph->version = 4;
	// iph->tos = 0;
	// iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	// iph->id = htonl (54321);	//Id of this packet
	// iph->frag_off = 0;
	// iph->ttl = 255;
	// iph->protocol = IPPROTO_TCP;
	// iph->check = 0;		//Set to 0 before calculating checksum
	// iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	// iph->daddr = sin.sin_addr.s_addr;

    // printf("datagram: %s\n", datagram);
    // printf("data: %s\n", data);
    

    // //Send the packet
    // if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    // {
    //     perror("sendto failed");
    // }
    // //Data send successfully
    // else
    // {
    //     printf ("Packet Send. Length : %d \n" , iph->tot_len);
    // }
    // // sleep for 1 seconds
    // sleep(1);

    // int bytes_recieved;

    // unsigned char *buffer = (unsigned char *) malloc(65536); //to receive data
    // memset(buffer,0,65536);
    // struct sockaddr saddr;
    // int saddr_len = sizeof (saddr);

    // bytes_recieved = recvfrom(s,buffer,65536,0,&saddr,(socklen_t *)&saddr_len);

    // // printf("&saddr: %s\n", &saddr);
    // printf("&saddr_len: %d\n", saddr_len);

    // printf ("response: %s\n", buffer);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



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
