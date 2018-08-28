#include <cstdio>
#include <iostream>
#include <string>
#include <libnet.h>
#include <pcap.h>

using namespace std;

const char *ip_expr = "ifconfig | awk '/inet addr/ {gsub(\"addr:\", \"\", $2); print $2}'";
const char *hw_expr = "ifconfig | awk '/HWaddr/ {gsub(\"HWaddr:\", \"\", $5); print $5}'";
const char *gateip_expr = "route | awk '/default/ {gsub(\"default\", \"\", $0); print $1}'";
const char *zero_mac = "00:00:00:00:00:00";

pair<string,string> get_network_info()
{
	FILE *ip_in,*hw_in;
	char buf[256];
	string tmp;
	pair<string,string> info;

	if(!(ip_in = popen(ip_expr,"r")))
		return info;

	fgets(buf,sizeof(buf),ip_in);
	tmp = string(buf);
	info.first = tmp.substr(0,tmp.size()-1);

	if(!(hw_in = popen(hw_expr,"r")))
		return info;

	fgets(buf,sizeof(buf),hw_in);
	tmp = string(buf);
	info.second = tmp.substr(0,tmp.size()-1); 

	fclose(ip_in);
	fclose(hw_in);

	return info;
}

string get_gateway_ip()
{
	FILE *gateway_in;
	char buf[256];
	string tmp = "";

	if(!(gateway_in = popen(gateip_expr,"r")))
		return tmp;

	fgets(buf,sizeof(buf),gateway_in);
	tmp = string(buf);
	tmp = tmp.substr(0,tmp.size()-1);

	fclose(gateway_in);
}

int main(int argc,char **argv)
{
	auto l = libnet_init(LIBNET_LINK,NULL,errbuf);
	auto a = get_network_info();
	auto gate_ip = get_gateway_ip();
	int len,len2;



	return 0;
}
