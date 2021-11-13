#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h> 
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h> //For errno - the error number


void* routine() 
{
    printf("Test pthreading\n");
    sleep(3);
    printf("Ending thread\n");
}

int main(int argc, char **argv) 
{

    pthread_t t1;
    pthread_t t2;
    
    pthread_create(&t1, NULL, &routine, NULL);
    pthread_create(&t2, NULL, &routine, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    return 0;

}