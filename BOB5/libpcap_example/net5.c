#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>

int main()
{
	libnet_t *handle;
	char errbuf[LIBNET_ERRBUF_SIZE],ip_addr_str[16];
	u_int32_t ip_addr;
	u_int16_t id,seq;
	char payload[] = "libnet :D";
	int bytes_written;

	handle = libnet_init(LIBNET_RAW4,NULL,errbuf);

	if(handle == NULL)
	{
		fprintf(stderr,"libnet_init() failed: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}
	
	libnet_seed_prand(handle);
	id = (u_int16_t)libnet_get_prand(LIBNET_PR16);
	
	printf("Destination IP address: ");
	scanf("%15s",ip_addr_str);

	ip_addr = libnet_name2addr4(handle,ip_addr_str,LIBNET_DONT_RESOLVE);

	if(ip_addr == -1)
	{
		fprintf(stderr,"Error converting IP address.\n");
		libnet_destroy(handle);
		exit(EXIT_FAILURE);
	}
	
	seq = 1;

	if(libnet_build_icmpv4_echo(ICMP_ECHO,0,0,id,seq,\
				(u_int8_t *)payload,sizeof(payload),handle,0)==-1)
	{
		fprintf(stderr,"Error building ICMP header: %s\n",\
			libnet_geterror(handle));
		libnet_destroy(handle);
		exit(EXIT_FAILURE);
	}

	if(libnet_autobuild_ipv4(LIBNET_IPV4_H + \
				LIBNET_ICMPV4_ECHO_H + sizeof(payload),\
				IPPROTO_ICMP,ip_addr,handle) == -1)
	{
		fprintf(stderr,"Error building IP header: %s\n",\
				libnet_geterror(handle));
		libnet_destroy(handle);
		exit(EXIT_FAILURE);
	}

	bytes_written = libnet_write(handle);

	if(bytes_written != -1)
		printf("%d bytes written.\n",bytes_written);
	else
		fprintf(stderr,"Error writing packet: %s\n",\
				libnet_geterror(handle));

	libnet_destroy(handle);
	
	return 0;
}
