#include "image_capture.h"

using namespace std;

int main(int argc, char **argv)
{
	bpf_u_int32 net,mask;
	string errmsg="",dev="";
	string filter_exp = "tcp";
	struct bpf_program fp;
	pcap_t *handle;

	dev = string((const char *)pcap_lookupdev((char *)errmsg.c_str()));

	if(dev=="")
	{
		fprintf(stderr,"Couldn't find default device: %s\n",errmsg.c_str());
		return 2;
	}

	if(pcap_lookupnet(dev.c_str(),&net,&mask,(char *)errmsg.c_str()))
	{
		fprintf(stderr,"Can't get netmask for device %s\n",errmsg.c_str());
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live((char *)dev.c_str(),BUFSIZ,1,1000,(char *)errmsg.c_str());

	if(handle==NULL)
	{
		fprintf(stderr,"Couldn't open device %s: %s\n",dev.c_str(),errmsg.c_str());
		return 2;
	}

	if(pcap_compile(handle,&fp,(char *)filter_exp.c_str(),0,net) == -1)
	{
		fprintf(stderr,"Couldn't parse filter %s: %s\n",filter_exp.c_str(),pcap_geterr(handle));
		return 2;
	}

	if(pcap_setfilter(handle,&fp) == -1)
	{
		fprintf(stderr,"Couldn't install filter %s: %s\n",filter_exp.c_str(),pcap_geterr(handle));
		return 2;
	}

	pcap_loop(handle,0,process_packet,NULL);

	pcap_close(handle);

	return 0;
}
