#include <cstdio>
#include <cstdlib>
#include <libnet.h>
#include <stdint.h>
#include <string>
#include <iostream>

using namespace std;

const char *gateip_expr = "route | awk '/default/ {gsub(\"default\", \"\", $0); print $1}'";

string get_gateway_ip()
{
	FILE *gateway_in;
	char buf[256];
	string tmp = "";

	if(!(gateway_in = popen(gateip_expr,"r")))
		return tmp;

	fgets(buf,sizeof(buf),gateway_in);
	tmp = string(buf);
	tmp = tmp.substr(0,tmp.size()-1);

	fclose(gateway_in);
}

int main()
{
	libnet_t *l;
	char errbuf[LIBNET_ERRBUF_SIZE],target_ip_addr_str[16];
	u_int32_t target_ip_addr, src_ip_addr;
	u_int8_t mac_broadcast_addr[6] = {0xff,0xff,0xff,0xff,0xff,0xff},\
	mac_zero_addr[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

	struct libnet_ether_addr *src_mac_addr;
	int bytes_written;

	l = libnet_init(LIBNET_LINK,NULL,errbuf);

	if(l==NULL)
	{
		fprintf(stderr,"libnet_init() failed: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}
	
	src_ip_addr = libnet_get_ipaddr4(l);

	if(src_ip_addr == -1)
	{
		fprintf(stderr,"Couldn't get own IP address %s\n",\
				libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	src_mac_addr = libnet_get_hwaddr(l);

	if ( src_mac_addr == NULL )
	{
		fprintf(stderr, "Couldn't get own IP address: %s\n",\
								libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	printf("Target IP address : ");
	scanf("%15s",target_ip_addr_str);


	target_ip_addr = libnet_name2addr4(l,target_ip_addr_str,\
			LIBNET_DONT_RESOLVE);

	if(target_ip_addr == -1)
	{
		fprintf(stderr, "Error converting IP address.\n");
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}


	if(libnet_autobuild_arp(ARPOP_REQUEST,\
				src_mac_addr->ether_addr_octet,\
				(u_int8_t*)(&src_ip_addr),mac_zero_addr,\
				(u_int8_t*)(&target_ip_addr),l) == -1)
	{
		fprintf(stderr, "Error building ARP header: %s\n",\
				libnet_geterror(l));
		libnet_destroy(l);
		exit(EXIT_FAILURE);
	}

	if(libnet_autobuild_ethernet(mac_broadcast_addr,\
				ETHERTYPE_ARP,l) == -1)
	{
		    fprintf(stderr, "Error building Ethernet header: %s\n",\
					        libnet_geterror(l));
			libnet_destroy(l);
			exit(EXIT_FAILURE);
	}

	bytes_written = libnet_write(l);
	if(bytes_written != -1)
		printf("%d bytes written.\n",bytes_written);
	else
		fprintf(stderr, "Error writing packet: %s\n",\
				        libnet_geterror(l));

	libnet_destroy(l);

	return 0;
}	
