#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>
#define BUFFSIZE 65535

int main(int argc, char *argv[]) {

struct iphdr
{
	unsigned int version:4;
	unsigned int ihl:4;
    u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	struct in_addr source;
	struct in_addr dest;
};

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
	printf("SRC  IP=%s\n",inet_ntoa(iphdr-> source));
	printf("DEST IP=%s\n",inet_ntoa(iphdr-> dest));
	printf("PROTOCOL = %d\n", iphdr-> protocol);

	return 0;
}
