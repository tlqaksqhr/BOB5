  #include <stdio.h>
  #include <pcap.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netinet/if_ether.h>
  #include <netinet/ip.h>
  #include <netinet/ip_icmp.h>
  #include <netinet/tcp.h>

  #define PCAP_CNT_MAX 10
  #define PCAP_SNAPSHOT 1024
  #define PCAP_TIMEOUT 100
        
  void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
        
  int main(int argc, char *argv[]) {
                char *dev;
                char errbuf[PCAP_ERRBUF_SIZE];
                bpf_u_int32 net;
                bpf_u_int32 netmask;
                struct in_addr net_addr, mask_addr;
                pcap_t *pd;
        
                if(!(dev = pcap_lookupdev(errbuf))) {
                        perror(errbuf);
                        exit(1);
                }
        
                if(pcap_lookupnet(dev, &net, &netmask, errbuf) < 0) {
                        perror(errbuf);
                        exit(1);
                }
        
                net_addr.s_addr = net;
                mask_addr.s_addr = netmask;
        
                printf("Device : %s\n", dev);
                printf("Net Address : %s\n", inet_ntoa(net_addr));
                printf("Netmask : %s\n", inet_ntoa(mask_addr));
        
                if((pd = pcap_open_offline(argv[1],errbuf)) == NULL) {
                        perror(errbuf);
                        exit(1);
                }
        
                if(pcap_loop(pd, PCAP_CNT_MAX, packet_view, 0) < 0) {
                        perror(pcap_geterr(pd));
                        exit(1);
                }
        
                pcap_close(pd);
        
                return 1;
        }
        /*
         * packet_view
         * print packets
         */
        void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)
         {
			    struct ethhdr *eth_hdr;
				struct ip *ip_hdr;
                int len;
        
                len = 0;

				eth_hdr = (struct ethhdr *)p;
				ip_hdr = (struct ethhdr *)(p+sizeof(eth_hdr));

				printf("Src Addr : %s\n",inet_ntoa(ntohl(ip_hdr->ip_src)));
				printf("Dst Addr : %s\n",inet_ntoa(ntohl(ip_hdr->ip_dst)));
        
                printf("PACKET\n");
                while(len < h->len) {
                        printf("%02x ", *(p++));
                        if(!(++len % 16))
                                printf("\n");
                }
                printf("\n");
        
                return ;
        }
