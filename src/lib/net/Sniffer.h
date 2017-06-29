#pragma once
#include <string>

using std::string;

class Sniffer
{
	public:
		Sniffer(string &dev, string &ip, int serverport);
		int CreateRawSocket();
		virtual int ParsePackage();
		virtual ~Sniffer();
	private:
		int GetNicId();
		int BindNic(int ifindex);
		//int CheckTcp(const struct iphdr* iph);
		string serverip;
		int port;
		string device;
		int sock_fd;
};