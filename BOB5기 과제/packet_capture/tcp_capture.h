#pragma once
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

