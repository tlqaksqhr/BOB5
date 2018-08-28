#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <linux/types.h>


#define BUFFSIZE 65535


int main(int argc, char *argv[]) {

	int fd;
	struct ether_header *eth;
	struct iphdr *iph;
	struct icmphdr *icmph;
	unsigned char buff[BUFFSIZE];
	unsigned char *p;

	if ((fd=open("./icmp2.pcap", O_RDONLY))>0)
	{
		read(fd, buff, BUFFSIZE);
	}

	eth = (struct ehter_header *)(buff+40);

	printf("Dest Mac Address : ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",eth->ether_dhost[0],eth->ether_dhost[1],\
			eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
	printf("Source Mac Address : ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n",eth->ether_shost[0],eth->ether_shost[1],\
			eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);

	if(ntohs(eth->ether_type)==ETHERTYPE_IP)
		printf("Type : IP\n");
	else if(ntohs(eth->ether_type)==ETHERTYPE_ARP)
		printf("Type : ARP\n");

	iph = (struct ether_header *)(buff+40+sizeof(eth));



	return 0;
}    
