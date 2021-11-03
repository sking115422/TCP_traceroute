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


int openRawConnection(char *TARGET, int portnum)
{
    struct hostent *he;
    struct in_addr **addr_list;
    struct in_addr addr;

    char target_copy [strlen(TARGET)];

    strcpy(target_copy, TARGET);

    char * first_str = strtok(target_copy, ".");

    printf("target: %s\n", TARGET);

    char *first_ip;
    if (checkStringIsNumeric (first_str) == 0)
    {
        he = gethostbyname(TARGET);
        if (he == NULL) { 
            herror("gethostbyname"); 
            exit(0);
        }

        printf("\nDNS INFO\n");
        printf("Official name is: %s\n", he->h_name);
        char *temp = inet_ntoa(*(struct in_addr*)he->h_addr);
        strcpy(first_ip, temp);
        printf("IP address: %s\n", first_ip);
        printf("All addresses: ");
        addr_list = (struct in_addr **)he->h_addr_list;
        for(int i = 0; addr_list[i] != NULL; i++) {
            printf("%s ", inet_ntoa(*addr_list[i]));
        }
        printf("\n");

    }
    else 
    {
        first_ip = TARGET;
    }

    int raw_tcp_socket;

    //creating socket
    raw_tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    struct sockaddr_in remote_address;

    remote_address.sin_family = AF_INET;
    remote_address.sin_port = htons(portnum);
    inet_aton(first_ip, &remote_address.sin_addr);

    
    //establishing TCP connection
    if ( connect(raw_tcp_socket, (struct sockaddr *) &remote_address, sizeof(remote_address)) != 0 )
    {
        close(raw_tcp_socket);
        perror("Error");
        exit(0);
    }

    printf("\nNew raw TCP socket created!\n");

    return raw_tcp_socket;
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


    int conn = openRawConnection(TARGET, atoi(DST_PORT));

    printf("done...");
}


/*

$ ./tcp_traceroute.py -h
usage: tcp_traceroute.py [-m MAX_HOPS] [-p DST_PORT] -t TARGET

optional arguments:
-h, --help   show this help message and exit
-m   MAX_HOPS  Max hops to probe (default = 30)
-p   DST_PORT  TCP destination port (default = 80)
-t   TARGET    Target domain or IP

*/