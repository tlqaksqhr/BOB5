#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <iostream>


void process_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);

using namespace std;

void conv_hw_addr(string mac_addr,unsigned char *addr)
{
	for(int i=0;i<6;i++)
		addr[i] = stoi(mac_addr.substr(3*i,2),nullptr,16);
}

int main(int argc,char **argv)
{

	char *dev; // 네트워크 디바이스 이름.
	char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지 버퍼.
	struct pcap_pkthdr header; // pcap 헤더.
	pcap_t *handle; // sniffing session

	/* 
	 * 기본 네트워크 디바이스의 이름을 가져오는 함수 에러버퍼의 주소를 인자로 받는다.
	 * 에러가 발생할 경우 NULL값을 리턴한다.
	 */
	dev = pcap_lookupdev(errbuf);
	memset(&header,0,sizeof(header)); 

	if(dev==NULL)
	{
		fprintf(stderr,"Couldn't find default device: %s\n",errbuf);
		return 2;
	}
	printf("Device : %s\n",dev);


	/*
	 * sniffing session을 열어주는 함수이다.
	 * 정확하게는 '이더넷 디바이스' 파일을 열고 이더넷 디바이스의 파일핸들을 받아오는 함수이다.
	 * */
	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	
	if(handle == NULL)
	{
		fprintf(stderr,"Couldn't open device : %s: %s\n",dev,errbuf);
		return 2;
	}

	char *buffer = new char[256];
	u_char test[ETH_ALEN];
	
	struct ethhdr *ethernet_hdr;
	struct arphdr *arp_header;
	struct sockaddr_in addr_inet;

	conv_hw_addr("08:00:27:24:68:ef",test);
	memcpy(ethernet_hdr->h_source,test,ETH_ALEN);
	memset(test,0,ETH_ALEN);
	conv_hw_addr("08:00:27:24:68:ef",test);
	memcpy(ethernet_hdr->h_dest,test,ETH_ALEN);
	ethernet_hdr->h_proto = htons(ETH_P_ARP);
	memcpy(buffer,ethernet_hdr,ETH_HLEN);
	/*
	arp_header->ar_hrd = htons(ARPHRD_ETHER);
	arp_header->ar_pro = htons(ETH_P_IP);
	arp_header->ar_hln = 6;
	arp_header->ar_pln = 4;
	arp_header->ar_op = htons(ARPOP_REQUEST);

	conv_hw_addr("08:00:27:24:68:ef",test);
	memcpy(arp_header->__ar_sha,test,ETH_ALEN);
	inet_aton("10.0.2.15",&addr_inet.sin_addr);
	memcpy(arp_header->ar_sip,htonl(addr_inet.sin_addr.s_addr),4);

	inet_aton("10.0.2.2",&addr_inet.sin_addr);
	conv_hw_addr("52:54:00:12:35:02",test);
	memcpy(arp_header->ar_tha,test,ETH_ALEN);
	memcpy(arp_header->ar_hip,htonl(addr_inet.sin_addr.s_addr),4);

	memcpy(buffer+ETH_HLEN,ethernet_hdr,sizeof(arp_header));
	*/
	pcap_inject(handle,buffer,ETH_HLEN);
	

	pcap_close(handle);
	
	return 0;
}
