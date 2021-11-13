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
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h> //For errno - the error number


char * getLocal_IP ()
{
    char localhost [256];
    char * local_ip;
    struct hostent * host_entry;
    int hostname;

    hostname = gethostname(localhost, sizeof(localhost));
    host_entry = gethostbyname(localhost);
    local_ip = inet_ntoa (*((struct in_addr*) host_entry->h_addr_list[0]));

    printf("Current Hostname: %s\n", localhost);
    printf("Host IP: %s\n", local_ip);

    return local_ip;
}

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

    getLocal_IP();

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

    for (int i = 0; i < max_hops; i++)
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

        // //Data part
        // data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        // strcpy(data , "test");
        
        //172.17.152.208


        //some address resolution
        strcpy(source_ip , "172.17.152.208");
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
        iph->saddr = inet_addr ( source_ip ); //Spoof the source ip address
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
        psh.source_address = inet_addr( source_ip );
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        pseudogram = malloc(psize);
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr));
        tcph->check = csum( (unsigned short*) pseudogram , psize);

        if (sendto (sendsock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
        {
            perror("sendto failed");
        }

        else
        {
            printf ("Packet Sent. Length : %d \n" , iph->tot_len);
        }

        struct sockaddr saddr;
        int saddr_size = sizeof(saddr);

        unsigned char * buf = (unsigned char *) malloc(65536);

        int bytes_recieved;
        if (bytes_recieved = recvfrom(recvsock_icmp, buf, 65536, 0, &saddr, &saddr_size) < 0)
        {
            perror("recv");
        }

        printf("bytes_recieved: %d\n", bytes_recieved);

    }

    close (sendsock);
    close (recvsock_icmp);
    close (recvsock_raw);

    printf("done...\n");

    return 0;

}



