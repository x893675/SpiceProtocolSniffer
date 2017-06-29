#include "Sniffer.h"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <string.h>
#include <arpa/inet.h>

#include "../spice/protocol.h"
#define BUFFER_MAX 2048





static int CheckTcp(const struct iphdr* iph, string s_ip, int s_port)
{
	if(!iph)
	{
		return 0;
	}
	char source_ip[INET_ADDRSTRLEN];
	char dest_ip[INET_ADDRSTRLEN];
	sprintf(source_ip,"%s",	inet_ntoa(*(struct in_addr*)&iph->saddr));
	//printf("Source IP address : %s\n",source_ip);
	sprintf(dest_ip,"%s",	inet_ntoa(*(struct in_addr*)&iph->daddr));
	//printf("Dest IP address: %s\n",dest_ip);

	if(strcmp(source_ip,s_ip.c_str()) == 0 || strcmp(dest_ip,s_ip.c_str()) == 0)
	{
		struct tcphdr * tcpheader = (struct tcphdr*)(iph + 1);
		int source_port = ntohs(tcpheader->source);
		int dest_port = ntohs(tcpheader->dest);
		printf("source port : %d\n",source_port);
		printf("dest port : %d\n",dest_port);

		if(dest_port == s_port)
		{
			struct SpiceLinkHeader* spicelkheader = (struct SpiceLinkHeader*)(tcpheader + 1);	
			printf("%d\n",spicelkheader->magic);
		}
	}
	else
	{
		//printf("not spice package\n");
	}
	return 0;
}

Sniffer::Sniffer(string &dev, string &ip, int serverport)
{
	this->device = dev;
	this->serverip = ip;
	this->port = serverport;
	sock_fd = 0;
}

Sniffer::~Sniffer()
{
	if(sock_fd != 0)
	{
		close(sock_fd);
		sock_fd = 0;
	}
}


int Sniffer::CreateRawSocket()
{
	sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock_fd == -1)
	{
		printf("socket %s.\n", strerror(errno));
		sock_fd = 0;
		return -1;
	}
	
	int ifindex = GetNicId();
	if(ifindex < 0)
	{
		printf("get nic id failed, %s.\n", strerror(errno));
		close(sock_fd);
		sock_fd = 0;
		return -1;
	}
	
	int result = BindNic(ifindex);
	if(result != 0)
	{
		close(sock_fd);
		sock_fd = 0;
		return -1;
	}
	
	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifindex;
	mr.mr_type    = PACKET_MR_PROMISC;
	if(setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
	{
		printf("setsockopt failed, %s.\n", strerror(errno));
		close(sock_fd);
		sock_fd = 0;
		return -1;
	}
	
	int mode_loss = 0;
	result = setsockopt(sock_fd, SOL_PACKET, PACKET_LOSS, (char*)&mode_loss, sizeof(mode_loss));
	if(result != 0)
	{
		printf("set PACKET_LOSS failed, %s.\n", strerror(errno));
		close(sock_fd);
		sock_fd = 0;
		return -1;
	}
	
/*	result = setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, (void *)&send_size, sizeof(send_size));
	if(result != 0)
	{
		printf("set send buffer size failed, %s.\n", strerror(errno));
		close(sock_fd);
		return -1;
	}
	printf("set send buffer size %d ok.\n", send_size);
	
	result = setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, (void *)&receive_size, sizeof(receive_size));
	if(result != 0)
	{
		printf("set receive buffer size failed, %s.\n", strerror(errno));
		close(sock_fd);
		return -1;
	}
	printf("set receive buffer size %d ok.\n", receive_size);*/
	
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 100;
	result = setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
	if(result != 0)
	{
		printf("set receive timeout failed, %s.\n", strerror(errno));
		close(sock_fd);
		sock_fd = 0;
		return -1;
	}
	
	//return sock_fd;
	return 0;
}

int Sniffer::GetNicId()
{
	struct ifreq ifr;
	
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device.c_str(), sizeof(ifr.ifr_name));
	
	if(ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1)
	{
		printf("ioctl %s.\n", strerror(errno));
		return -1;
	}
	
	return ifr.ifr_ifindex;
}

int Sniffer::BindNic(int ifindex)
{
	struct sockaddr_ll	sll;
	int					err;
	socklen_t			errlen = sizeof(err);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if(bind(sock_fd, (struct sockaddr *) &sll, sizeof(sll)) == -1)
	{
		printf("bind %s.\n", strerror(errno));
		return -1;
	}

	if(getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1)
	{
		printf("getsockopt %s.\n", strerror(errno));
		return -2;
	}

	if(err > 0)
	{
		printf("bind %s.\n", strerror(err));
		return -2;
	}

	return 0;
}

int Sniffer::ParsePackage()
{
	if(sock_fd == 0)
	{
		return -1;
	}

	int n_read;
	struct ether_header* etherh;
	struct iphdr* iph;
	char buf[BUFFER_MAX];
	
	while(1)
	{
		n_read = recvfrom(sock_fd, buf, 2048, 0, NULL, NULL);
		//14(ether_header)+20(ip_header)+8(tcp/udp header)
		if(n_read < 42)
		{
			//printf("Incomplete header, packet corrupt\n");
			continue;
		}

		etherh = (struct ether_header*)buf;
		iph = (struct iphdr*)(etherh+1);
		
		if(iph->protocol == IPPROTO_TCP)
		{
			CheckTcp(iph, serverip, port);
		}
	}
}