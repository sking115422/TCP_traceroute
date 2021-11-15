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



int main(int argc, char **argv) 
{
    
    for(int i = 1; i < 4; i++)
    {

        time_t startTime;
        time_t now;
        float elapsedTime;
        float setTime = 5;

        time(&startTime);
        while (elapsedTime < setTime) {
            //do something...

            now = time(NULL);
            elapsedTime = difftime(now, startTime);
        }
    } 



    return 0;

}