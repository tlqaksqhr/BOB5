#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>

#define ETHERNET_ADDR_LEN 6

typedef struct ethernet_header{
	u_char ether_dhost[ETHERNET_ADDR_LEN]; // Dest Mac Addr
	#define IP_V4 0x0800 
	u_char ether_shost[ETHERNET_ADDR_LEN]; // Source Mac Addr
	u_short ether_type;	// 상위프로토콜이 무엇인지 알려주는 Type값. IP_V4인 경우에는 0x0800이다.
}HDR_ETHERNET;

typedef struct ip_header{
	u_char vhl; // version & header length(정확히는 헤더의 필드 개수)
	u_char tos; // service type
	u_short len; // 데이터 길이
	u_short id; // identification
	u_short off; // flag and fragment
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1fff // fragment_offset을 가져와주기 위해 필요한 마스킹 값이다.(fragment offset value : off 변수의 하위 13bit)
	u_char ttl; // time to live (패킷의 생명주기 건너간 라우터 개수로 카운팅)
	u_char protocol; // 프로토콜 종류
#define PROTO_ICMP 1 
#define PROTO_IGMP 2 
#define PROTO_TCP 6 
#define PROTO_UDP 17
	u_short checksum; // 패킷 검증에 필요한 체크섬
	struct in_addr ip_src,ip_dst; // source,dst ip
}HDR_IP;
#define IP_HL(ip) (((ip)->vhl) & 0x0f) // vhl의 하위 4바이트(Header 크기)를 가져온다.
#define IP_V(ip) (((ip)->vhl) >> 4) // vhl의 상위 4바이트(Version)을 가져온다. 비교를 편하게 하기 위해 4 bit shifting 해주었다.

typedef struct tcp_header
{
	u_short s_port; // 출발 포트번호
	u_short d_port; // 목적지 포트번호
	u_int seq; // 시퀸스 번호
	u_int ack; // 응답번호
	u_char th_offx2; // 데이터 오프셋
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags; // syn,ack등의 플래그를 나타내 주는 값
	u_short window; // sliding window 크기(* Sliding Window : 패킷 송수신시 네트워크 상황이나, 자신의 상황을 고려하여 받을 수 있는 최대의 버퍼크기)
	u_short check; // 패킷 체크섬(무결성 검사)
	u_short urg; // urgent 포인터(해당 패킷을 우선적으로 처리하라는 의미)
}HDR_TCP;

HDR_ETHERNET *sniff_ethhdr;
HDR_IP *sniff_ip;
HDR_TCP *sniff_tcp;

void process_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
void print_mac_address(const char *message,u_char *mac_addr);

int main(int argc,char **argv)
{

	char *dev; // 네트워크 디바이스 이름.
	char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지 버퍼.
	char filter_exp[] = "port 80 and host 1.234.27.228"; // 패킷 필터링 옵션.
	struct bpf_program fp; // 패킷 필터링 구조체
	struct pcap_pkthdr header; // pcap 헤더.
	pcap_t *handle; // sniffing session
	bpf_u_int32 mask,net; // 각각 디바이스의 네트워크 마스크, 네트워크 주소

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
	 * 네트워크 디바이스에 설정되어있는 네트워크 주소와 네트워크 마스킹(대역폭을 결정)을 가져오는 함수이다.
	 * 첫번째 인자는 네트워크 디바이스의 이름이다.
	 * 두번째 인자는 네트워크 주소값을 가지고 있는 변수의 주소이다.
	 * 세번째 인자는 네트워크 마스킹값을 가지고 있는 변수의 주소이다.
	 * 네번째 인자는 에러버퍼 메시지의 포인터를 인자로 갖는다.
	 * 에러가 발생하는 경우 -1을 리턴한다.
	 * */
	if(pcap_lookupnet(dev,&net,&mask,errbuf) == -1)
	{
		fprintf(stderr,"Can't get netmask for device %s\n",dev);
		net = 0;
		mask = 0;
	}

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

	/*
	 * 
	 * 핸들값을　인자로　받아　데이터링크 계층에서 어떤 프로토콜을 쓰는지 판별을 해주는 함수이다.
	 * 리턴값에　대한　자세한 내용은 http://www.tcpdump.org/linktypes.html를　참조하면　된다．
	 * */
	if (pcap_datalink(handle) != DLT_EN10MB) 
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return 2;
	}


	/*
	 * 패킷 필터링 명령어를 bpf_program 형식에 맞게 컴파일해주는 함수. 
	 * session_handle과 bpfprogram 구조체,필터 명령어와 넷마스크를 인자로 받는다. 
	 * */
	if(pcap_compile(handle,&fp,filter_exp,0,net) == -1)
	{
		fprintf(stderr,"Couldn't parse filter : %s: %s\n",filter_exp,pcap_geterr(handle));
		return 2;
	}

	/*
	 * 패킷을 필터링 해주는 함수이다.
	 * 인자로는 session_handle과 bpfprogram 구조체를 인자로 받는다.
	 * */

	if(pcap_setfilter(handle,&fp) == -1)
	{
		fprintf(stderr,"Couldn't install filter : %s: %s\n",filter_exp,pcap_geterr(handle));
		return 2;
	}

	pcap_loop(handle,0,process_packet,NULL);

	pcap_close(handle);

	/*
	pcap_next 함수는 패킷을 1번만 정해진 크기만큼 받아온다
	따라서 패킷이 오고가지 않는 경우 패킷을 받지 못하므로, 반복적으로 받게 해준다.
	사실 pcap_loop 함수를 쓰면 된다.
	
	while(1)
	{
		packet = pcap_next(handle,&header);
		printf("Jacked a packet with length of [%d]\n",header.len);
	}
	*/
	
	return 0;
}

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
