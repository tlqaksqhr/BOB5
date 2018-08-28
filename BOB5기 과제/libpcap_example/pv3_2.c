#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
//#include <linux/ip.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define BUFFSIZE 65535

int main(int argc, char *argv[]) {

    int fd;
	struct iphdr *iphdr; 
    char buff[BUFFSIZE];
    char *p = buff;
	int i;

    if ((fd=open("./icmp2.pcap", O_RDONLY))>0)
    {
		read(fd, buff, BUFFSIZE);
    }

	p+=24+16+14;
	iphdr =(struct iphdr *) p; 
	printf("SRC  IP=%s\n",inet_ntoa(*(struct in_addr *) &iphdr->saddr));
	printf("DEST IP=%s\n",inet_ntoa(*(struct in_addr *) &iphdr->daddr));;
	printf("PROTOCOL = %d\n", iphdr->protocol);

}
