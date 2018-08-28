#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <netinet/ether.h>
//#include <netinet/ip.h>
#include <arpa/inet.h>
#define BUFFSIZE 65535

int main(int argc, char *argv[]) {

	int fd;
	struct iphdr *ip_hdr; 
    char buff[BUFFSIZE];
    char *p = buff;
	int i;

    if ((fd=open("./icmp2.pcap", O_RDONLY))>0)
    {
    	read(fd, buff, BUFFSIZE);
    }

	p+=24+16+14;
	ip_hdr =(struct iphdr *)p; 
	printf("Src : %s\n",inet_ntoa(*(struct in_addr *)&ip_hdr->saddr));
	printf("Dst : %s\n",inet_ntoa(*(struct in_addr *)&ip_hdr->daddr));
	printf("Protocol : %x\n",ip_hdr->protocol);

}
