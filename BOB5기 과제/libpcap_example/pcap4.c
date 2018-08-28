#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>

void process_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);

int main(int argc,char **argv)
{

	char *dev; // 네트워크 디바이스 이름.
	char errbuf[PCAP_ERRBUF_SIZE]; // 에러 메시지 버퍼.
	char filter_exp[] = "port 22"; // 패킷 필터링 옵션.
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

	if(pcap_compile(handle,&fp,filter_exp,0,net) == -1)
	{
		fprintf(stderr,"Couldn't parse filter : %s: %s\n",filter_exp,pcap_geterr(handle));
		return 2;
	}
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
