#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>

int main()
{
	libnet_t *handle;
	char errbuf[LIBNET_ERRBUF_SIZE];

	handle = libnet_init(LIBNET_RAW4,NULL,errbuf);

	if(handle == NULL)
	{
		fprintf(stderr,"libnet_init() failed : %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	libnet_destroy(handle);

	return 0;
}
