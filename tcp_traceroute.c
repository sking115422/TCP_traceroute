#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> 
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <netdb.h>

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>




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


struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


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
                printf("-h Show this help message and exit\n");
                printf("-m Max hops to probe (default = 30)\n");
                printf("-p TCP destination port (default = 80)\n");
                printf("-t Target domain or IP\n");
                exit(0);
        }
    }

    int portnum = atoi(DST_PORT);
    char * target_ip = resolveToIP(TARGET, portnum);
    int max_hops = atoi(MAX_HOPS);

    char * local_ip = get_Local_Broadcast_IP();

    printf("\nTCP_Traceroute to %s (%s), %s hops max, TCP SYN to port %s\n", TARGET, target_ip, MAX_HOPS, DST_PORT);
    printf("\n");
    
    int sendsock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);

    int one = 1;
    const int *val = &one;

    if (setsockopt (sendsock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    int recvsock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int recvsock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 500000;

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

        //Datagram to represent the packet
        char datagram[4096];
        char source_ip[32];

        // char *data; 
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

        // printf ("\n\nsource_ip: %s\n\n", source_ip);

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
        iph->saddr = inet_addr (source_ip); //Spoof the source ip address
        iph->daddr = sin.sin_addr.s_addr;

        //Ip checksum
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);

        //TCP Header
        tcph->source = htons (12345);
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
        tcph->window = htons (5840); /* maximum allowed window size */
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

        printf("%d   ", i);

        char new_icmp_packet_source [16];
        char old_icmp_packet_source [16];
        memset(new_icmp_packet_source, 0 , 16);
        memset(old_icmp_packet_source, 0 , 16);



        for (int j = 0; j < 3; j++)
        {   
            clock_t begin = clock();

            if (sendto (sendsock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            {
                perror("sendto failed");
            }

            clock_t end = 0;

            unsigned char * buffer = (unsigned char *) malloc(65536);
            memset(buffer, 0 ,65536);

            struct sockaddr saddr;
            int saddr_size = sizeof(saddr);

            int bytes_recieved = recvfrom(recvsock_icmp, buffer, 65536, 0, &saddr, &saddr_size);
            if(bytes_recieved < 0)
            {
                printf("*   ");
            }
            else
            {   
                end = clock();

                struct ethhdr *eth = (struct ethhdr *)(buffer);

                // printf("\nEthernet Header\n");
                // printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
                // printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
                // printf("\t|-Protocol : %d\n",eth->h_proto);

                struct sockaddr_in source;
                struct sockaddr_in dest;

                unsigned short iphdrlen;
                struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = ip->saddr;
                // memset(&dest, 0, sizeof(dest));
                // dest.sin_addr.s_addr = ip->daddr;

                // printf("\nIP Header\n");
                // printf("\t|-Version : %d\n",(unsigned int)ip->version);
                // printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
                // printf("\t|-Type Of Service : %d\n",(unsigned int)ip->tos);
                // printf("\t|-Total Length : %d Bytes\n",ntohs(ip->tot_len));
                // printf("\t|-Identification : %d\n",ntohs(ip->id));
                // printf("\t|-Time To Live : %d\n",(unsigned int)ip->ttl);
                // printf("\t|-Protocol : %d\n",(unsigned int)ip->protocol);
                // printf("\t|-Header Checksum : %d\n",ntohs(ip->check));
                // printf("\t|-Destination IP : %s\n",inet_ntoa(dest.sin_addr));

                strcpy((char *) new_icmp_packet_source, inet_ntoa(source.sin_addr));

                if (strcmp(new_icmp_packet_source, old_icmp_packet_source) != 0)
                {   
                    resolveToHostname(new_icmp_packet_source);
                    printf("(%s)   ", new_icmp_packet_source);
                }
                
                strcpy(old_icmp_packet_source, new_icmp_packet_source);
            }

            double time_spent;

            if (end != 0)
            {
                time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
                printf ("%.3f ms   ", time_spent * 1000);
            }

        }

        printf("\n\n");

    }

    close (sendsock);
    close (recvsock_icmp);
    close (recvsock_raw);

    printf("done...\n");

    return 0;

}



