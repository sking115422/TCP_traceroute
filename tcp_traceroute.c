

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*

TCP TRACEROUTE PROGRAM

Written By: Spencer King

This program emulates the standard implimentation of traceroute in Linux however instead of sending and recieving UDP packets we use TCP packets.

*/
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////HEADER FILES

//General header files
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

//Header files for socket programming
#include <sys/types.h>
#include <sys/socket.h>

//Header files for network packet manipulation
#include <netinet/ip.h> 
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

//Header files for more general network needs
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


////HELPER FUNCTIONS AND STRUCTS


//Global flag for ending raw packet gathering 
int search_end_flag;

void exitflag(int sig)
{
    search_end_flag = 1;
}


//Function to check whether or not a string is numeric and return 1 if numeric and 0 if not
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


//Function to resolve a hostname to an IP address
char * resolveToIP(char *TARGET, int portnum)
{
    struct hostent *he;
    struct in_addr **addr_list;
    struct in_addr addr;

    char target_copy [strlen(TARGET)];

    strcpy(target_copy, TARGET);

    char * first_str = strtok(target_copy, ".");

    char *target_ip;
    if (checkStringIsNumeric (first_str) == 0)
    {
        he = gethostbyname(TARGET);

        if (he == NULL) 
        { 
            herror("gethostbyname"); 
            exit(0);
        }

        char *temp = inet_ntoa(*(struct in_addr*)he->h_addr);
        strcpy(target_ip, temp);
    }
    else 
    {
        target_ip = TARGET;
    }

    return target_ip;
}


//Function to resolve an IP to a hostname
int resolveToHostname (char * ip)
{   
    struct hostent *h;
    struct sockaddr_in sin;
    char domain[512];
    sin.sin_addr.s_addr=inet_addr(ip);

    h = gethostbyaddr((char *)&sin.sin_addr.s_addr, sizeof(struct in_addr), AF_INET);

    if (h!=(struct hostent *)0)
    {
        strcpy(domain,h->h_name);
        printf("%s ", domain);
    }
    else
    {
        printf("%s ", ip);
    }
    
    return 0;
}


//Function to return local private broadcast IP of current machine
char * get_Local_Broadcast_IP ()
{
    system("hostname -I > localip.txt");

    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("localip.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    read = getline(&line, &len, fp);
    fclose(fp);

    system("rm localip.txt");

    char * ip = strtok(line, " ");

    if (strstr(ip, "172") == NULL)
    {
        while( ip != NULL && strstr(ip, "172") == NULL) 
        {
            ip = strtok(NULL, " ");
        }
    }

    return ip;
}


//Structure to server as place holder for TCP header during TCP header checksum calculation
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


//General checksum calculator
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;

    while(nbytes>1) 
    {
        sum+=*ptr++;
        nbytes-=2;
    }

    if(nbytes==1) 
    {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


//DRIVER FUNCTION


int main(int argc, char **argv) 
{
    
    int option_val = 0;

    //Default values for command line arguments
    char * MAX_HOPS = "30";
    char * DST_PORT = "80";
    char * TARGET = "google.com";

    //Using getopt to parse command-line arguments
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
                printf("-h Show this help message and exit\n");
                printf("-m Max hops to probe (default = 30)\n");
                printf("-p TCP destination port (default = 80)\n");
                printf("-t Target domain or IP\n");
                exit(0);
        }
    }

    //Assigning command-line args to usable values
    int portnum = atoi(DST_PORT);
    char * target_ip = resolveToIP(TARGET, portnum);
    int max_hops = atoi(MAX_HOPS);

    //Setting default local address and port info
    char * local_ip = get_Local_Broadcast_IP();
    int tcp_local_port = 12345;

    //Setting maximum number of seconds to search for raw tcp packets
    int max_search_time = 4;

    //Setting socket time out values
    struct timeval tv;
    tv.tv_sec = 4;
    tv.tv_usec = 400000;

    //TCP_traceroute intro program statement
    printf("\nTCP_Traceroute to %s (%s), %s hops max, TCP SYN to port %s\n", TARGET, target_ip, MAX_HOPS, DST_PORT);
    printf("\n");
    
    //Creating raw sending socket
    int sendsock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);

    //Setting socket option IP_HDRINCL to actually include our manually created packet headers in the packet being sent
    int one = 1;
    const int *val = &one;

    if (setsockopt (sendsock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    //Creating receiving sockets: one for ICMP packets and one (RAW) for TCP packets 
    int recvsock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int recvsock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    //Setting socket options for both receiving sockets to only block or time out after a certain number of seconds (we set this earlier as "tv")    
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

    //Variable to terminate program after target is successfully found
    int global_success = 0;

    //Master for-loop that controls number of hops we will send probes for
    for (int i = 1; i < max_hops + 1; i++)
    {   
        
        //Flag used to caputure if ICMP packet are returned from target destination
        int icmp_from_target = 0;

        //Ending program if target is reached successfully
        if (global_success == 1)
        {
            printf("SYN-ACK or RST packet received from target server. Target successfully reached!\n\n");
            exit(1);
        }

        //Datagram to represent the packet
        char datagram[4096];
        char source_ip[32];

        //Holds our packet to be sent 
        char *pseudogram;

        //zero out the packet buffer
        memset (datagram, 0, 4096);

        //IP header
        struct iphdr *iph = (struct iphdr *) datagram;

        //TCP header
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
        struct sockaddr_in sin;
        struct pseudo_header psh;

        //Some address resolution
        strcpy(source_ip , local_ip);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(portnum);
        sin.sin_addr.s_addr = inet_addr (target_ip);

        //Fill in the IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
        iph->id = htonl (54321); //Id of this packet
        iph->frag_off = 0;
        iph->ttl = i;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0; //Set to 0 before calculating checksum
        iph->saddr = inet_addr (source_ip); //source ip address
        iph->daddr = sin.sin_addr.s_addr;

        //IP checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);

        //TCP Header
        tcph->source = htons (tcp_local_port);
        tcph->dest = htons (portnum);
        tcph->seq = random ();
        tcph->ack_seq = 0;
        tcph->doff = 5; //tcp header size
        tcph->fin=0;
        tcph->syn=1;
        tcph->rst=0;
        tcph->psh=0;
        tcph->ack=0;
        tcph->urg=0;
        tcph->window = htons (5840); //maximum allowed window size 
        tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
        tcph->urg_ptr = 0;


        //Now the TCP checksum
        psh.source_address = inet_addr(source_ip);
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        pseudogram = malloc(psize);
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
        tcph->check = csum( (unsigned short*) pseudogram , psize);

        //Printing to console the current number of hops we are probing for
        printf("%d   ", i);

        //Creating variables to handle printing of ICMP packet source IP addresses
        char new_icmp_packet_source [16];
        char old_icmp_packet_source [16];
        memset(new_icmp_packet_source, 0 , 16);
        memset(old_icmp_packet_source, 0 , 16);

        //Creating variables to handle printing of ICMP packet source IP addresses
        char new_raw_packet_source [16];
        char old_raw_packet_source [16];
        memset(new_raw_packet_source, 0 , 16);
        memset(old_raw_packet_source, 0 , 16);

        //Inner for-loop to control the number of probes sent each hop (3 in this case as in standard traceroute)
        for (int j = 0; j < 3; j++)
        {   

            //Variable for tracking latency (time take to send and receive packets)
            struct timeval tv1;
            struct timeval tv2;
            gettimeofday(&tv1, NULL);

            //Variable to allow time to be printed
            int print_time = 1;

            //Variable that accounts for if SYN-ACK or RST packets have been recieved from target (this = success)
            int success = 0;

            //Sending packet out
            if (sendto (sendsock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            {
                perror("sendto failed");
            }
            
            //Setting variables to recieve packet
            unsigned char * buffer_icmp = (unsigned char *) malloc(65535);   //65535 is max packet size
            memset(buffer_icmp, 0, 65535);
            struct sockaddr saddr_icmp;
            int saddr_size_icmp = sizeof(saddr_icmp);

            //Attempting to receive ICMP packet
            int bytes_recieved_icmp = recvfrom(recvsock_icmp, buffer_icmp, 65535, 0, &saddr_icmp, &saddr_size_icmp);

            //If ICMP packet is recieved
            if(bytes_recieved_icmp > 0)
            {

                //End timer for latency
                gettimeofday(&tv2, NULL);

                //Setting up variable and structs to read in ICMP packet information
                struct iphdr *ip = (struct iphdr*)(buffer_icmp);
                struct sockaddr_in source;

                //Saving source IP from ICMP packet
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = ip->saddr;

                //Storing source IP as pointer
                strcpy((char *) new_icmp_packet_source, inet_ntoa(source.sin_addr));

                //Following series of If-statements make sure the source address is only printed if it is a new source address
                if (strcmp(new_icmp_packet_source, old_icmp_packet_source) != 0)
                {   
                    resolveToHostname(new_icmp_packet_source);
                    printf("(%s)   ", new_icmp_packet_source);
                }

                if (strcmp(inet_ntoa(source.sin_addr), target_ip) == 0)
                {
                    icmp_from_target = 1;
                }
                
                strcpy(old_icmp_packet_source, new_icmp_packet_source);
            }

            //If no ICMP packet is recieved 
            else
            {
                
                ////Setting up variable and structs to read in RAW packet information
                unsigned char * buffer_raw = (unsigned char *) malloc(65535);
                memset(buffer_raw, 0 ,65535);
                struct sockaddr saddr_raw;
                int saddr_size_raw = sizeof(saddr_raw);

                //Variable to save destination reached (source IP of received packet)
                char * dest_reached_ip = NULL;
                
                //Timer to only let while loop run for a specific period of time
                search_end_flag = 0;
                signal(SIGALRM, exitflag);
                alarm(max_search_time);

                //While loop to collect raw packets until timer is up
                while (search_end_flag == 0)
                {

                    //Attempting to receive raw TCP packets
                    int bytes_recieved = recvfrom(recvsock_raw, buffer_raw, 65535, 0, &saddr_raw, &saddr_size_raw);

                    //Variables to parse packet
                    unsigned char * buf_ptr = buffer_raw;
                    int ptr_mover = 0;

                    //Structures and variable to store packet data
                    struct iphdr *ip = (struct iphdr*)(buf_ptr + ptr_mover);    //IP header
                    ptr_mover = ptr_mover + sizeof(struct iphdr);

                    struct tcphdr *tcp_hdr = (struct tcphdr *)(buf_ptr + ptr_mover);    //TCP header
                    ptr_mover = ptr_mover + ntohs(ip->tot_len) - sizeof(struct iphdr);

                    struct sockaddr_in source;
                    struct sockaddr_in dest;

                    memset(&source, 0, sizeof(source));
                    source.sin_addr.s_addr = ip->saddr;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_addr.s_addr = ip->daddr;

                    //Storing the IP of the recieved packed
                    dest_reached_ip = inet_ntoa(source.sin_addr);

                    //Filtering incoming packets until we find one that has correct parameters:
                    //////received packet source ip == our target ip
                    //////received packet destination port number == our port number
                    //////received packet flags are either SYN-ACK or RST
                    //If all conditions are met flags are set, latency timer is stopped, and we break out of the loop
                    if (strcmp(inet_ntoa(source.sin_addr), target_ip) == 0 && (int) ntohs(tcp_hdr->dest) == tcp_local_port && ((int) tcp_hdr->th_flags == 18 || (int) tcp_hdr->th_flags == 4))
                    {
                        gettimeofday(&tv2, NULL);
                        success = 1;
                        global_success = 1;
                        break;
                    }

                }
                
                //If correct correct raw TCP packet (SYN-ACK or RST) is recieved we will print its source IP
                if (success == 1)
                {

                    //Following series of If-statements make sure the source address is only printed if it is a new source address
                    strcpy((char *) new_raw_packet_source, dest_reached_ip);

                    if (strcmp(new_raw_packet_source, old_raw_packet_source) != 0)
                    {   
                        resolveToHostname(new_raw_packet_source);
                        printf("(%s)   ", new_raw_packet_source);
                    }
                    
                    strcpy(old_raw_packet_source, new_raw_packet_source);
                }

                //If correct raw TCP packet is not recieved we print *
                else
                {
                    printf("*   ");
                    print_time = 0;
                }
                
            }

            //if "*" is not printed we print the latency time 
            double time_elapsed;
            if (print_time == 1)
            {
                time_elapsed = (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec);

                if (time_elapsed > max_search_time * .8)
                    printf ("%.3f ms   ", time_elapsed * 1000 - (double) (max_search_time * 1000 * .99)); 
                else
                    printf ("%.3f ms   ", time_elapsed * 1000);
            }

        }

        //In some cases we will receive an ICMP from our target IP. 
        //In these cases, we print it to console to inform the user the destination has been reached but has responded with ICMP not expected SYN-ACK or RST. 
        if (icmp_from_target == 1)
        {
            printf ("\n |");
            printf ("\n '--> ICMP packet received from target IP... Target has been reached!");
        }

        printf("\n\n");

    }

    //Closing all of our sockets
    close (sendsock);
    close (recvsock_icmp);
    close (recvsock_raw);

    //Print target not reachable after max number of hops is reached and the target is not found
    printf("Target destination not reachable...\n");

    return 0;

}




////// HELPFULL PRINT STATEMENTS

////Ethernet

// printf("\nEthernet Header\n");
// printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
// printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
// printf("\t|-Protocol : %d\n",eth->h_proto);

//// IP

// printf("\nIP Header\n");
// printf("\t|-Version : %d\n",(unsigned int)ip->version);
// printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
// printf("\t|-Total Length : %d Bytes\n", ntohs(ip->tot_len));
// printf("\t|-Time To Live : %d\n",(unsigned int)ip->ttl);
// printf("\t|-Protocol : %d\n",(unsigned int)ip->protocol);
// printf("\t|-Header Checksum : %d\n", ntohs(ip->check));
// printf("\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
// printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));

//// TCP

// printf("\nTCP Header\n");
// printf("\t|-Source Port : %d\n", ntohs(tcp_hdr->th_sport));
// printf("\t|-Destination Port : %d\n", ntohs(tcp_hdr->dest));
// printf("\t|-Seq Number : %ld\n", (long) tcp_hdr->th_seq);
// printf("\t|-Ack Number : %ld\n", (long) tcp_hdr->th_ack);
// printf("\t|-Flags : %d\n", (int) tcp_hdr->th_flags);