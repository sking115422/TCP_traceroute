
//General header files
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/select.h>

//Hedaer files for mutli-threading
#include <pthread.h>

//Header files for socket programming
#include <sys/types.h>
#include <sys/socket.h>

//Header files for network packet manipulation

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <asm/byteorder.h>


//Header files for more general network needs
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>




struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


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


struct recv_args 
{
    int socket;
    unsigned char * buffer;
    struct sockaddr saddr;
    int saddr_size;
};

struct recv_return
{
    int bytes_recieved;
    unsigned char * buffer;
    clock_t clock_end;


};


 void * recvPackets (void * arg)
{

    struct recv_args vars = *(struct recv_args *) arg;
    struct recv_return rtn;

    int socket = vars.socket;
    unsigned char * buffer = vars.buffer;
    struct sockaddr saddr = vars.saddr;
    int saddr_size = vars.saddr_size;

    int bytes_recieved = recvfrom(socket, buffer, 65536, 0, &saddr, &saddr_size);

    rtn.clock_end = clock();
    rtn.bytes_recieved = bytes_recieved;
    rtn.buffer = buffer;

    struct recv_return *result_ptr = (struct recv_return*) malloc(sizeof(struct recv_return));

    *result_ptr = rtn;

    return (void*) result_ptr; 
}




int writeBufToFile (unsigned char * buf, int i, int j, int bytes_recieved)
{

    char path [50];
    snprintf(path, sizeof(path), "bin_files/file_%d%d", i, j);

    system("mkdir bin_files");

    FILE * fp;

    fp = fopen(path, "wb");

    if (fp == NULL)
        perror("file_open");


    size_t elem_writ = fwrite(&buf, 1, bytes_recieved, fp);

    fclose(fp);
    
    if(elem_writ == 0)
    {
        printf("error writting\n");
    }


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
            clock_t end_icmp;
            clock_t end_raw;

            if (sendto (sendsock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            {
                perror("sendto failed");
            }

            struct sockaddr saddr_icmp;
            int saddr_size_icmp = sizeof(saddr_icmp);

            struct recv_args input_icmp;
            struct recv_return *res_icmp;

            unsigned char * buffer_icmp = (unsigned char *) malloc(65536);
            memset(buffer_icmp, 0 ,65536);

            input_icmp.buffer = buffer_icmp;
            input_icmp.saddr = saddr_icmp;
            input_icmp.saddr_size = saddr_size_icmp;
            input_icmp.socket = recvsock_icmp;

            pthread_t t_icmp;



            struct sockaddr saddr_raw;
            int saddr_size_raw = sizeof(saddr_raw);

            struct recv_args input_raw;
            struct recv_return *res_raw;

            unsigned char * buffer_raw = (unsigned char *) malloc(65536);
            memset(buffer_raw, 0 ,65536);

            input_raw.buffer = buffer_raw;
            input_raw.saddr = saddr_raw;
            input_raw.saddr_size = saddr_size_raw;
            input_raw.socket = recvsock_raw;

            pthread_t t_raw;



            if (pthread_create(&t_icmp, NULL, &recvPackets, &input_icmp) != 0)
            {
                perror("pthread_icmp");
            }

            if (pthread_create(&t_raw, NULL, &recvPackets, &input_raw) != 0)
            {
                perror("pthread_raw");
            }

            if (pthread_join(t_icmp, (void **) &res_icmp) != 0)
            {
                perror("pthread_icmp_join");
            }

            if (pthread_join(t_raw, (void **) &res_raw) != 0)
            {
                perror("pthread_icmp_join");
            }

            if (res_icmp->bytes_recieved < 0)
            {
                

                // printf("bytes_recieved: %d\n\n", res_raw->bytes_recieved);

                // writeBufToFile(res_raw->buffer, i, j, res_raw->bytes_recieved);

                unsigned char * buf_ptr = res_raw->buffer;
                int ptr_mover = 0;

                char * dest_reached_ip = NULL;

                while (ptr_mover < res_raw->bytes_recieved)
                { 

                    struct iphdr *ip = (struct iphdr*)(buf_ptr + ptr_mover);
                    ptr_mover = ptr_mover + sizeof(struct iphdr);

                    struct tcphdr *tcp_hdr = (struct tcphdr *)(buf_ptr + ptr_mover);
                    ptr_mover = ptr_mover + ntohs(ip->tot_len) - sizeof(struct iphdr);


                    struct sockaddr_in source;
                    struct sockaddr_in dest;

                    memset(&source, 0, sizeof(source));
                    source.sin_addr.s_addr = ip->saddr;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_addr.s_addr = ip->daddr;

                    if (strcmp(inet_ntoa(dest.sin_addr), source_ip) == 0 && ((int) tcp_hdr->th_flags == 18 || (int) tcp_hdr->th_flags == 4))
                    {

                        printf("\nIP Header\n");
                        printf("\t|-Version : %d\n",(unsigned int)ip->version);
                        printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
                        printf("\t|-Total Length : %d Bytes\n", ntohs(ip->tot_len));
                        printf("\t|-Time To Live : %d\n",(unsigned int)ip->ttl);
                        printf("\t|-Protocol : %d\n",(unsigned int)ip->protocol);
                        printf("\t|-Header Checksum : %d\n", ntohs(ip->check));
                        printf("\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
                        printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));

                        printf("\nTCP Header\n");
                        printf("\t|-Source Port : %d\n", ntohs(tcp_hdr->th_sport));
                        printf("\t|-Destination Port : %d\n", ntohs(tcp_hdr->dest));
                        printf("\t|-Seq Number : %ld\n", (long) tcp_hdr->th_seq);
                        printf("\t|-Ack Number : %ld\n", (long) tcp_hdr->th_ack);
                        printf("\t|-Flags : %d\n", (int) tcp_hdr->th_flags);

                        dest_reached_ip = inet_ntoa(source.sin_addr);
                        end_raw = res_raw->clock_end;

                    }

                }

                if (dest_reached_ip != NULL)
                {
                    resolveToHostname(dest_reached_ip);
                    printf("(%s)   ", dest_reached_ip);

                    double time_spent_raw;
                    time_spent_raw = (double)(end_raw - begin) / CLOCKS_PER_SEC;
                    printf ("%.3f ms   ", time_spent_raw * 1000);

                    printf("Target destination reached\n");

                    exit(1);
                }

                else 
                {
                    printf("*   ");
                }
                
            }

            else
            {   
                

                end_icmp = res_icmp->clock_end;

                struct sockaddr_in source;
                struct sockaddr_in dest;

                unsigned short iphdrlen;
                struct iphdr *ip = (struct iphdr*)(res_icmp->buffer);
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = ip->saddr;

                strcpy((char *) new_icmp_packet_source, inet_ntoa(source.sin_addr));

                if (strcmp(new_icmp_packet_source, old_icmp_packet_source) != 0)
                {   
                    resolveToHostname(new_icmp_packet_source);
                    printf("(%s)   ", new_icmp_packet_source);
                }
                
                strcpy(old_icmp_packet_source, new_icmp_packet_source);

                double time_spent_icmp;

                time_spent_icmp = (double)(end_icmp - begin) / CLOCKS_PER_SEC;
                printf ("%.3f ms   ", time_spent_icmp * 1000);               

            }

            free(res_icmp);
            free(res_raw);

        }

        printf("\n\n");

    }

    close (sendsock);
    close (recvsock_icmp);
    close (recvsock_raw);

    printf("Target destination not reachable...\n");

    return 0;

}


////For layer 2

// struct ethhdr *eth = (struct ethhdr *)(buffer);

// printf("\nEthernet Header\n");
// printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
// printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
// printf("\t|-Protocol : %d\n",eth->h_proto);

////For layer 3 

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
// printf("\t|-Source IP : %s\n",inet_ntoa(source.sin_addr));