#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc,char **argv)
{

	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[] = "port 80";
	struct bpf_program fp;
	pcap_t *handle;
	bpf_u_int32 mask,net;

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

	if(pcap_compile(handle,&fp,filter_exp,0,net) == -1)
	{
		fprintf(stderr,"Couldn't parse filter : %s: %s\n",filter_exp,pcap_geterr(handle));
		return 2;
	}
	if(pcap_setfilter(handle,&fp) == -1)
	{
		fprintf(stderr,"Couldn't install filter : %s: %s\n",filter_exp,pcap_geterr(handle));
		return 2;
	}

	

	return 0;
}
