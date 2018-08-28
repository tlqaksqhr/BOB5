#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include "tcp_capture.h"

void print_mac_address(const char *message,u_char *mac_addr)
{
	printf("%s :",message);
	printf("%x:%x:%x:%x:%x:%x\n",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
}

void process_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	int len,offset,cnt=0;
	u_char *data;
	sniff_ethhdr = (HDR_ETHERNET *)packet;
	
	// 엔디안을 형식에 알맞게 변환하여 비교를 해야함. 
	if(ntohs(sniff_ethhdr->ether_type)!=IP_V4)
		return ;

	sniff_ip = (HDR_IP *)(packet + sizeof(HDR_ETHERNET));
	/* 
	 * IP_HL(sniff_ip) 가 받아오는 값은 필드의 개수이다. 따라서 byte길이를 구하려면 IP_HL(sniff_ip)*4 를 해주어야 한다.
	 * 추가적으로 IP_HL의 필드 개수로 ip헤더인지 검증을 할 수 있고, optional 헤더의 여부도 알 수 있다.
	 */
	len = IP_HL(sniff_ip)*4; 

	if(len<20 || sniff_ip->protocol != PROTO_TCP)
		return ;

	sniff_tcp = (HDR_TCP *)(packet + sizeof(HDR_ETHERNET) + len);
	offset = TH_OFF(sniff_tcp)*4;
	data = (u_char *)(packet + sizeof(HDR_ETHERNET) + len + offset);

	print_mac_address("Source Mac : ",sniff_ethhdr->ether_shost);
	print_mac_address("Dest Mac : ",sniff_ethhdr->ether_dhost);

	printf("Source IP Address : %s\n",inet_ntoa(sniff_ip->ip_src));
	printf("Dest IP Address : %s\n",inet_ntoa(sniff_ip->ip_dst));

	printf("Source Port : %d\n",ntohs(sniff_tcp->s_port));
	printf("Dest Port : %d\n",ntohs(sniff_tcp->d_port));

	printf("========================================== Data ==============================================\n");
	while(*data!=NULL)
	{
		printf("%c",*data);
		data++;
	}
	printf("==============================================================================================\n");

}
