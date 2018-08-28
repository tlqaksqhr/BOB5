#include <cstdio>
#include <cstdlib>
#include <libnet.h>
#include <stdint.h>
#include <pcap.h>
#include <string>
#include <iostream>

using namespace std;


const char *gateip_expr = "route | awk '/default/ {gsub(\"default\", \"\", $0); print $1}'";
libnet_t *l;
pcap_t *handle;
struct pcap_pkthdr header;
u_int32_t src_ip_addr;
struct libnet_ether_addr *src_mac_addr;



int init_service();
void get_network_info();
string get_gateway_ip();
void send_arp(string target_ip);
void destroy();



int init_service()
{
	char errbuf[LIBNET_ERRBUF_SIZE];
	char errbuf2[PCAP_ERRBUF_SIZE];
	char *dev;

	l = libnet_init(LIBNET_LINK,NULL,errbuf);

	if(l==NULL)
	{
		fprintf(stderr,"libnet_init() failed: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	dev = pcap_lookupdev(errbuf);
	
	memset(&header,0,sizeof(header));

	if(dev==NULL)
	{
		fprintf(stderr,"Couldn't find default device: %s\n",errbuf2);
		return 2;
	}

	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

	if(handle == NULL)
	{
		fprintf(stderr,"Couldn't open device : %s: %s\n",dev,errbuf);
		return 2;
	}

}

void get_network_info()
{
	src_ip_addr = libnet_get_ipaddr4(l);

	if(src_ip_addr == -1)
	{
		fprintf(stderr,"Couldn't get own IP address %s\n",\
				libnet_geterror(l));
		destroy();
		exit(EXIT_FAILURE);
	}

	src_mac_addr = libnet_get_hwaddr(l);

	if ( src_mac_addr == NULL )
	{
		fprintf(stderr, "Couldn't get own IP address: %s\n",\
								libnet_geterror(l));
		destroy();
		exit(EXIT_FAILURE);
	}
	/*
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",src_mac_addr->ether_addr_octet[0],src_mac_addr->ether_addr_octet[1],\
			src_mac_addr->ether_addr_octet[2],src_mac_addr->ether_addr_octet[3],\
			src_mac_addr->ether_addr_octet[4],src_mac_addr->ether_addr_octet[5]);
	*/
}

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

void send_arp(string target_ip)
{
	int bytes_written;
	char *buf;

	libnet_ether_addr *mac_broadcast_addr;
	libnet_ether_addr *mac_zero_addr;

	memset(mac_broadcast_addr,-1,sizeof(mac_broadcast_addr));
	memset(mac_zero_addr,0,sizeof(mac_zero_addr));

	buf = new char[target_ip.length()+1];
	strcpy(buf,target_ip.c_str());

	u_int32_t target_ip_addr = libnet_name2addr4(l,buf,\
			LIBNET_DONT_RESOLVE);
	

	if(target_ip_addr == -1)
	{
		fprintf(stderr, "Error converting IP address.\n");
		destroy();
		exit(EXIT_FAILURE);
	}


	if(libnet_autobuild_arp(ARPOP_REQUEST,\
				src_mac_addr->ether_addr_octet,\
				(u_int8_t*)(&src_ip_addr),mac_zero_addr->ether_addr_octet,\
				(u_int8_t*)(&target_ip_addr),l) == -1)
	{
		fprintf(stderr, "Error building ARP header: %s\n",\
				libnet_geterror(l));
		destroy();
		exit(EXIT_FAILURE);
	}

	if(libnet_autobuild_ethernet(mac_broadcast_addr->ether_addr_octet,\
				ETHERTYPE_ARP,l) == -1)
	{
		    fprintf(stderr, "Error building Ethernet header: %s\n",\
					        libnet_geterror(l));
			destroy();
			exit(EXIT_FAILURE);
	}

	bytes_written = libnet_write(l);
	if(bytes_written != -1)
		printf("%d bytes written.\n",bytes_written);
	else
		fprintf(stderr, "Error writing packet: %s\n",\
				        libnet_geterror(l));
}

void destroy()
{
	libnet_destroy(l);
	pcap_close(handle);
}

int main(int argc,char **argv)
{
	if(argc!=2)
	{
		printf("Usage : %s [ip_addr] \n",argv[0]);
		exit(0);
	}

	string target_ip = string(argv[1]);

	init_service();

	get_network_info();

	send_arp(target_ip);
	destroy();

	return 0;
}	
