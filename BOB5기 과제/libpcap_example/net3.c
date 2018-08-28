#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>

int main()
{
	libnet_t *handle;
	char errbuf[LIBNET_ERRBUF_SIZE];
	char ip_addr_str[16],mac_addr_str[18];
	u_int32_t ip_addr;
	u_int8_t *ip_addr_p, *mac_addr;
	int i,length;

	handle = libnet_init(LIBNET_RAW4,NULL,errbuf);

	if(handle == NULL)
	{
		fprintf(stderr,"libnet_init() failed: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	printf("IP address: ");
	scanf("%15s",ip_addr_str);

	ip_addr = libnet_name2addr4(handle,ip_addr_str,LIBNET_DONT_RESOLVE);

	if(ip_addr != -1)
	{
		ip_addr_p = (u_int8_t*)(&ip_addr);
		printf("Address read: %d.%d.%d.%d\n",ip_addr_p[0],ip_addr_p[1],ip_addr_p[2],ip_addr_p[3]);
	}
	else
		fprintf(stderr,"Error converting IP address.\n");


	printf("MAC address: ");
	scanf("%s17s",mac_addr_str);

	mac_addr = libnet_hex_aton(mac_addr_str,&length);

	if(mac_addr != NULL)
	{
		printf("Address read: ");
		for(i=0;i<length;i++)
		{
			printf("%02X",mac_addr[i]);
			if(i<length-1)
				printf(":");
		}
		printf("\n");

		free(mac_addr);
	}
	else
		fprintf(stderr,"Error converting MAC address.\n");

	libnet_destroy(handle);

	return 0;
}
