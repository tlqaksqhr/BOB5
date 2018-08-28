	#include <stdio.h>
	#include <stdlib.h>
        #include <pcap.h>
        #include <sys/socket.h>
        #include <netinet/in.h>
        #include <arpa/inet.h>
        
        int main(int argc, char *argv[]) {
                char *dev;
                char errbuf[PCAP_ERRBUF_SIZE];
                bpf_u_int32 net;
                bpf_u_int32 mask;
                struct in_addr net_addr, mask_addr;
                
                /* look up device */
                if(!(dev = pcap_lookupdev(errbuf))) {
                        perror(errbuf);
                        exit(1);
                }
                
                /* get addresses associated with device */
                if(pcap_lookupnet(dev, &net, &mask, errbuf) < 0) {
                        perror(errbuf);
                        exit(1);
                }
                
                net_addr.s_addr = net;
                mask_addr.s_addr = mask;
                
                printf("Device : %s\n", dev);
                printf("Net Address : %s\n", inet_ntoa(net_addr));
		printf("%x\n", ntohl(net_addr.s_addr));
                printf("Netmask : %s\n", inet_ntoa(mask_addr));
		printf("size : %d\n", sizeof(struct timeval));
		printf("size : %d\n", sizeof(struct pcap_pkthdr));
		printf("size : %d\n", sizeof(struct pcap_file_header));
                
                return 1;
        }
