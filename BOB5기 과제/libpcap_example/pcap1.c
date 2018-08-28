#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc,char **argv)
{
	/*
	char *dev = argv[1];

	printf("Device : %s\n", dev);
	*/

	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	dev = pcap_lookupdev(errbuf);

	if(dev==NULL)
	{
		fprintf(stderr,"Couldn't find default device: %s\n",errbuf);
		return 2;
	}
	printf("Device : %s\n",dev);

	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	
	if(handle == NULL)
	{
		fprintf(stderr,"Couldn't open device : %s: %s\n",dev,errbuf);
		return 2;
	}

	
	return 0;
}
