#include <string>
#include <iostream>
#include <unordered_set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define TCP_PROTOCOL 0x06
#define INIT_POS 7

using namespace std;

void dump(char *buf, size_t len);

const char *method[7] = {"GET","POST","HEAD","PUT","DELETE","TRACE","CONNECT"};
unordered_set<string> filter_list;
bool cond = false;
FILE *flog;

/* returns packet id */
static u_int32_t process_pkt (struct nfq_data *tb)
{
  int id = 0;
  struct nfqnl_msg_packet_hdr *ph;
  struct nfqnl_msg_packet_hw *hwph;
  u_int32_t mark,ifi;
  int ret,payload_size;
  unsigned char *data,*payload;


  struct iphdr *iph;
  struct tcphdr *tcph;

  ph = nfq_get_msg_packet_hdr(tb);

  if (ph) {
    id = ntohl(ph->packet_id);
    printf("hw_protocol=0x%04x hook=%u id=%u ",
      ntohs(ph->hw_protocol), ph->hook, id);
  }

  hwph = nfq_get_packet_hw(tb);

  if (hwph) {
    int i, hlen = ntohs(hwph->hw_addrlen);

    printf("hw_src_addr=");
    for (i = 0; i < hlen-1; i++)
    printf("%02x:", hwph->hw_addr[i]);
    printf("%02x ", hwph->hw_addr[hlen-1]);
  }  

  mark = nfq_get_nfmark(tb);
  if (mark)
    printf("mark=%u ", mark);

  ifi = nfq_get_indev(tb);
  if (ifi)
    printf("indev=%u ", ifi);

  ifi = nfq_get_outdev(tb);
  if (ifi)
    printf("outdev=%u ", ifi);
  ifi = nfq_get_physindev(tb);
  if (ifi)
    printf("physindev=%u ", ifi);

  ifi = nfq_get_physoutdev(tb);
  if (ifi)
    printf("physoutdev=%u ", ifi);

  ret = nfq_get_payload(tb, &data);
  if (ret >= 0)
    printf("payload_len=%d ", ret);

  fputc('\n', stdout);

  iph = (struct iphdr *)data;

  if(iph->protocol != TCP_PROTOCOL)
	return id;
	
  tcph = (struct tcphdr *)(data + (iph->ihl << 2));
  payload_size = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
  payload = (data + ((iph->ihl << 2) + (tcph->doff << 2)));

  bool expr = false;

  for(int i=0;i<7;i++)
	  expr = expr || (memcmp((const char *)payload,(const char *)method[i],strlen(method[i]))==0);

  if(expr)
  {
	  string tmp = string((const char*)payload);
	  int url_start = tmp.find("Host: ") + strlen("Host: ");
	  int url_end = tmp.find("\r\n",url_start);
	  int len = url_end - url_start;

	  string url = tmp.substr(url_start,len);

	  if(filter_list.find(url) != filter_list.end())
	  {
	  	fprintf(flog,"Site is blocked! [%s]\n",url.c_str());
		cond = true;
	  }
  }

  return id;
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
	u_int32_t id = process_pkt(nfa); 

	if(cond==false)
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	else
	{
		cond = false;
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
}

void dump(char *buf, size_t len) {
  size_t i;

  unsigned char *tmp = (unsigned char *)buf;

  for (i = 0; i < len; i++) {
    printf("%02c ", *tmp++);
    if ((i + 1) % 16 == 0)
      printf("\n");
  }
  printf("\n");
  fflush(stdout);
}

int main(int argc, char **argv)
{
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096] __attribute__ ((aligned));
  char fbuf[512];

  system("iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0");

  FILE *pFile = fopen("mal_site.txt","r");

  while(fgets(fbuf,512,pFile) != NULL)
  {
	  int pos = INIT_POS;
	  for(;(fbuf[pos]!='\n' && fbuf[pos]!='/');pos++);

	  filter_list.insert(string(fbuf,INIT_POS,pos-INIT_POS));
  }
  fclose(pFile);


  printf("opening library handle\n");
  h = nfq_open();
  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }

  printf("binding this socket to queue '0'\n");
  qh = nfq_create_queue(h,  0, &callback, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  fd = nfq_fd(h);

  for (;;) {
    if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
  		flog = fopen("log.txt","a+"); 
		nfq_handle_packet(h, buf, rv);
		fclose(flog);
      	continue;
    }

    if (rv < 0 && errno == ENOBUFS) {
      printf("losing packets!\n");
      continue;
    }
    perror("recv failed");
    break;
  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

#ifdef INSANE
  printf("unbinding from AF_INET\n");
  nfq_unbind_pf(h, AF_INET);
#endif

  printf("closing library handle\n");
  nfq_close(h);
  exit(0);
}
