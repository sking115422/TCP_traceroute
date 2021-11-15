#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h> //For errno - the error number

int global_var;

void exitflag(int sig)
{
    global_var = 1;
}

int main(int argc, char **argv) 
{
    
    for(int i = 1; i < 4; i++)
    {
        global_var = 0;
        signal(SIGALRM, exitflag);
        alarm(5);
        while (global_var == 0) {
            
            
            printf("this thing %d\n", i);
            sleep(1);



        }
    } 



    return 0;

}