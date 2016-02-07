#include <stdio.h>
#include <string.h>
#include <net/if.h> //struct ifreq (interface request)  linux/if.hでもよい
#include <net/ethernet.h> //ETH_P_ALL
#include <sys/ioctl.h> //SIOCGIFFLAG SIOCSIFFLAG SIOCGIFINDEX 
#include <netinet/ip.h> //struct iphdr (struct ipもある)
#include <netinet/if_ether.h> //struct ether_arp
#include <netinet/tcp.h> //struct tcp
#include <netpacket/packet.h> //struct sockaddr_ll
#include <poll.h>

#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

char *ip_ntoa(u_int32_t ip) {
	u_char *d = (u_char *)&ip;
	static char str[15];
	sprintf(str, "%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
	return str;
}

char *mac_ntoa(u_char *d) {
	static char str[18];
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
	return str;
}

char *ip_ntoa2(u_char *d) {
	static char str[15];
	sprintf(str, "%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
	return str;
}

char *ip6_ntoa(struct in6_addr ip6) {
	static char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip6, str, INET6_ADDRSTRLEN);
	return str;
}

struct in6_addr ip6_aton(char *str) {
	struct in6_addr ip6;
	inet_pton(AF_INET6, str, &ip6);
	return ip6;
}

void printEtherHeader(u_char *buf) {
	struct ether_header *eth;
	eth = (struct ether_header *)buf;
	printf("----------- ETHERNET -----------\n");
	printf("Dst MAC addr   : %17s \n", mac_ntoa(eth->ether_dhost));
	printf("Src MAC addr   : %17s \n", mac_ntoa(eth->ether_shost));
	int type = ntohs(eth->ether_type);
	printf("Ethernet Type  : 0x%04x\n", ntohs(eth->ether_type));//2バイト以上扱う時はntoh-
}

void printIPHeader(u_char *buf) {
	struct iphdr *ptr;
	ptr = (struct iphdr *)buf;
	printf("----------- IP -----------\n");
	printf("version=%u\n", ptr->version);
	printf("ihl=%u\n", ptr->ihl);
	printf("tos=%x\n", ptr->tos);
	printf("tot_len=%u\n", ntohs(ptr->tot_len));
	printf("id=%u\n", ntohs(ptr->id));
	printf("ttl=%u\n", ptr->ttl);
	printf("protocol=%u\n", ptr->protocol);
	printf("src addr=%s\n", ip_ntoa(ptr->saddr));
	printf("dst addr=%s\n", ip_ntoa(ptr->daddr));
}

void printArp(u_char *buf) {
	struct ether_arp *arp;
	arp = (struct ether_arp *)buf;
	printf("----------- ARP ----------\n");
	printf("arp_hrd=%u\n", ntohs(arp->arp_hrd));
	printf("arp_pro=%u\n", ntohs(arp->arp_pro));
	printf("arp_hln=%u\n", arp->arp_hln);
	printf("arp_pln=%u\n", arp->arp_pln);
	printf("arp_op=%u\n", ntohs(arp->arp_op));
	printf("arp_sha=%s\n", mac_ntoa(arp->arp_sha));
	printf("arp_spa=%s\n", ip_ntoa2(arp->arp_spa));
	printf("arp_tha=%s\n", mac_ntoa(arp->arp_tha));
	printf("arp_tpa=%s\n", ip_ntoa2(arp->arp_tpa));
	//	printf("arp_tpa=%s\n",ip_ntoa(*((u_int32_t *)arp->arp_tpa)));
}

void printTcpHeader(u_char *buf) {
	struct tcphdr *ptr;
	ptr = (struct tcphdr *)buf;
	printf("src port = %u\n", ntohs(ptr->source));
	printf("dst port = %u\n", ntohs(ptr->dest));
}

void printIP6Header(u_char *buf) {
	struct ip6_hdr *ptr;
	ptr = (struct ip6_hdr *)buf;
	printf("---------- IPv6 ----------\n");
	printf("src addr=%s\n", ip6_ntoa(ptr->ip6_src));
	printf("dst addr=%s\n", ip6_ntoa(ptr->ip6_dst));
}

int checkICMPv6(u_char *buf) {
	struct ip6_hdr *ptr;
	ptr = (struct ip6_hdr *)buf;
	if (ptr->ip6_nxt == 0x3A) {
		printf("icmp!---");
		//icmpタイプチェック
		ptr += sizeof(struct ip6_hdr);
		struct icmp *icmp_ptr;
		icmp_ptr = (struct icmp *)ptr;
		printf("type: 0x%x\n", icmp_ptr->icmp_type);
		if (icmp_ptr->icmp_type == 0x85) {
			printf("soliciation!\n");
			//
		}else if (icmp_ptr->icmp_type == 0x86 ||
			icmp_ptr->icmp_type == 0x0) {
			printf("advertise!\n");
			//srcチェック
			ptr -= sizeof(struct ip6_hdr);
			if (strcmp(ip6_ntoa(ptr->ip6_src), "fe80::a00:27ff:fe58:6bcc") == 0) {
				//一致していたら
				return 0;
			}
		}
	}
	return 1;
}

int analyzePacket(u_char *buf) {
	u_char *ptr;
	struct ether_header *eth;
	struct iphdr *ip;
	//printEtherHeader(buf);
	ptr = buf;
	eth = (struct ether_header *)ptr;
	ptr += sizeof(struct ether_header);
	ip = (struct iphdr *)ptr;
	switch (ntohs(eth->ether_type)) {
	case ETH_P_IP:
		/*
		printIPHeader(ptr);
		if(ip->protocol==6){
		ptr+=((struct iphdr *)ptr)->ihl*4;
		printTcpHeader(ptr);
		}
		*/
		//return 0;
		break;
	case ETH_P_IPV6:
		printf("IPv6 Packet\n");
		printIP6Header(ptr);
		return checkICMPv6(ptr);
		break;
	case ETH_P_ARP:
		printArp(ptr);
		break;
	default:
		printf("unknown\n");
	}
	return 1;
}

int initRawSocket(char *dev) {
	struct ifreq ifr;
	int soc, size;
	struct sockaddr_ll sa;// これがないとbindできない
	soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	//初期化
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name) - 1);

	ioctl(soc, SIOCGIFINDEX, &ifr); //ifrにeth0の情報格納

	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = ifr.ifr_ifindex;
	bind(soc, (struct sockaddr *)&sa, sizeof(sa));//ifをbind, bindしないとすべてのifが対象

	ioctl(soc, SIOCGIFFLAGS, &ifr); //ifrにeth0の情報格納
	ifr.ifr_flags |= IFF_PROMISC; //promisc オプションを付加
	ioctl(soc, SIOCSIFFLAGS, &ifr); //ifrの情報を設定
	return soc;
}

u_char* changeIP6SD(u_char *buf, int flag) {
	struct ip6_hdr *ptr;
	buf += sizeof(struct ether_header);
	ptr = (struct ip6_hdr *)buf;
	char *sd[2];
	sprintf(sd[0], "2002::a00:27ff:fea9:d6a1");
	sprintf(sd[1], "2001::1000");
	if (flag == 0) {
		ptr->ip6_src = ip6_aton(sd[0]);
	}
	else {
		ptr->ip6_dst = ip6_aton(sd[1]);
	}
	ptr -= sizeof(struct ether_header);
	return (u_char *)ptr;
}

u_char* changeDest(u_char *buf, int flag) {
	struct ether_header *ptr;
	ptr = (struct ether_header *)buf;
	u_int8_t host[2][6] = {
		{ 0x08, 0x00, 0x27, 0xdc, 0x98, 0xe3 },
		{ 0x08, 0x00, 0x27, 0x58, 0x6b, 0xcc }
	};
	int i;
	for (i = 0; i<sizeof(host[0]) / sizeof(host[0][0]); i++) {
		ptr->ether_dhost[i] = host[flag][i];
	}
	return (u_char *)ptr;
}

int main() {
	int i, size, flag;
	u_char buf[65535];
	u_char *bufv6;
	char *dev[2] = { "eth3","eth4" };
	struct pollfd iflist[2];
	int packet_num = 0;

	for (i = 0; i<2; i++) {
		iflist[i].fd = initRawSocket(dev[i]);
		iflist[i].events = POLLIN;
	}

	printf("listen.\n");

	while (1) {
		switch (poll(iflist, 2, 100)) {
		case -1:
			perror("poll");
			break;
		case 0:
			break;
		default:
			for (i = 0; i<2; i++) {
				if (iflist[i].revents&(POLLIN)) {
					size = read(iflist[i].fd, buf, sizeof(buf));
					printf("recv from %s (%d octets)\n", dev[i], size);
					flag = analyzePacket(buf);
					if (flag) {
						bufv6 = changeIP6SD(buf, !i);
						write(iflist[!i].fd, changeDest(bufv6, !i), size);
						printf("send to %s (%d octets)\n", dev[!i], size);
					}
					printf("num: %d\n", packet_num++);
				}
			}
		}
	}
}
