#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

int main(int argc,char **argv)
{
	libnet_t *handle;
	char errbuf[LIBNET_ERRBUF_SIZE];

	if(argc == 1)
	{
		fprintf(stderr,"Usage: %s device\n",argv[0]);
		exit(EXIT_FAILURE);
	}

	handle = libnet_init(LIBNET_RAW4,argv[1],errbuf);

	if(handle == NULL)
	{
		fprintf(stderr,"libnet_init() failed: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	libnet_destroy(handle);

	return 0;
}
