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
#include <netinet/icmp6.h>
#include <netinet/udp.h>

#define ETHER_CHANGE 1
#define IPV6_CHANGE 1
#define CHECKSUM 1



int printIP6Header2(struct ip6_hdr *ip6, FILE *fp);
int analyzeIP6(u_char *data, int size);
u_int16_t chacksum2(u_char *data1, int len1, u_char *data2, int len2);


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
	printf("src addr=%s\n", ip6_ntoa(ptr->ip6_src));
	printf("dst addr=%s\n", ip6_ntoa(ptr->ip6_dst));
}

int checkICMPv6(u_char *buf) {
	struct ip6_hdr *ptr;
	ptr = (struct ip6_hdr *)buf;
	if (ptr->ip6_nxt == 0x3A) {
		printf("icmp---");
		//icmpタイプチェック
		ptr += sizeof(struct ip6_hdr);
		struct icmp *icmp_ptr;
		icmp_ptr = (struct icmp *)ptr;
		printf("type: 0x%x\n", icmp_ptr->icmp_type);
		if (icmp_ptr->icmp_type == 0x85) {
			//printf("soliciation!\n");
			//
		}else if (icmp_ptr->icmp_type == 0x86 ||
			icmp_ptr->icmp_type == 0x0) {
			//printf("advertise!\n");
			//srcチェック
			ptr -= sizeof(struct ip6_hdr);
			if (strcmp(ip6_ntoa(ptr->ip6_src), "fe80::a00:27ff:fe58:6bcc") == 0) {
				//一致していたら
				printf("icmp-del\n");
				return 0;
			}
		}
	}
	return 1;
}

int printICMP6(struct icmp6_hdr *icmp6, FILE *fp){
	fprintf(fp, "icmp--------------------\n");
	fprintf(fp, "icmp_type = %u,", icmp6->icmp6_type);
	fprintf(fp, "icmp6_code = %u,", icmp6->icmp6_code);
	fprintf(fp, "icmp6_cksum = %u\n", ntohs(icmp6->icmp6_cksum));

	if(icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129){
		fprintf(fp, "icmp6_id = %u,", ntohs(icmp6->icmp6_id));
		fprintf(fp, "icmp6_seq = %u\n", ntohs(icmp6->icmp6_seq));
	}

	return 0;
}

int printTcp(struct tcphdr *tcphdr, FILE *fp){
	fprintf(fp, "tcp--------------------\n");
	fprintf(fp, "source=%u,", ntohs(tcphdr->source));
	fprintf(fp, "dest=%u\n", ntohs(tcphdr->dest));
	fprintf(fp, "seq=%u\n", ntohl(tcphdr->seq));
	fprintf(fp, "ack_seq=%u\n", ntohl(tcphdr->ack_seq));
	fprintf(fp, "doff=%u,", tcphdr->doff);
	fprintf(fp, "urg=%u,", tcphdr->urg);
	fprintf(fp, "ack=%u,", tcphdr->ack);
	fprintf(fp, "psh=%u,", tcphdr->psh);
	fprintf(fp, "rst=%u,", tcphdr->rst);
	fprintf(fp, "syn=%u,", tcphdr->syn);
	fprintf(fp, "fin=%u\n", tcphdr->fin);
	fprintf(fp, "th_win=%u,", ntohs(tcphdr->window));
	fprintf(fp, "th_sum=%u,", ntohs(tcphdr->check));
	fprintf(fp, "th_urp=%u\n", ntohs(tcphdr->urg_ptr));
	return 0;
}

int printUdp(struct udphdr *udphdr, FILE *fp){
	fprintf(fp, "udp--------------------\n");
	fprintf(fp, "source=%u,", ntohs(udphdr->source));
	fprintf(fp, "dest=%u\n", ntohs(udphdr->dest));
	fprintf(fp, "len=%u,", ntohs(udphdr->len));
	fprintf(fp, "check=%u,", ntohs(udphdr->check));
	return 0;
}

int printIP6Header2(struct ip6_hdr *ip6, FILE *fp){
	fprintf(fp, "ip6--------------------\n");
	fprintf(fp, "ip6_flow = %x,", ip6->ip6_flow);
	fprintf(fp, "ip6_plen = %d,", ntohs(ip6->ip6_plen));
	fprintf(fp, "ip6_nxt = %u,", ip6->ip6_nxt);
	fprintf(fp, "ip6_hlim = %d\n", ip6->ip6_hlim);
	fprintf(fp, "ip6_src = %s\n", ip6_ntoa(ip6->ip6_src));
	fprintf(fp, "ip6_dst = %s\n", ip6_ntoa(ip6->ip6_dst));

	return 0;
}

int analyzeICMP6(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct icmp6_hdr *icmp6;

	ptr = data;
	lest = size;

	if(lest < sizeof(struct icmp6_hdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct icmp_hdr)\n", lest);
		return -1;
	}
	icmp6 = (struct icmp6_hdr *)ptr;
	ptr += sizeof(struct icmp6_hdr);
	lest -= sizeof(struct icmp6_hdr);

	printICMP6(icmp6, stdout);

	return 0;
}

int analyzeTcp(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct tcphdr *tcphdr;

	ptr = data;
	lest = size;

	if(lest < sizeof(struct tcphdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct tcphdr)\n", lest);
		return -1;
	}

	tcphdr = (struct tcphdr *)ptr;
	ptr += sizeof(struct tcphdr);
	lest -= sizeof(struct tcphdr);

	printTcp(tcphdr, stdout);

	return 0;
}

int analyzeUdp(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct udphdr *udphdr;

	ptr = data;	
	lest = size;

	if(lest < sizeof(struct udphdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct udphdr)\n", lest);
		return -1;
	}

	udphdr = (struct udphdr *)ptr;
	ptr += sizeof(struct udphdr);
	lest -= sizeof(struct udphdr);

	printUdp(udphdr, stdout);

	return 0;
}

int analyzeIP6(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct ip6_hdr *ip6;
	int len;

	ptr = data;
	lest = size;

	if(lest < sizeof(struct ip6_hdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct ip6_hdr)\n", lest);
		return -1;
	}
	ip6 = (struct ip6_hdr *)ptr;
	ptr += sizeof(struct ip6_hdr);
	lest -= sizeof(struct ip6_hdr);

	if(ip6->ip6_dst.s6_addr[0] == 0xff){
		return 0;
	}

	printIP6Header2(ip6, stdout);

	if(ip6->ip6_nxt == IPPROTO_ICMPV6){
		len = ntohs(ip6->ip6_plen);
		if(checkIP6Sum(ip6, ptr, len) == 0){
			fprintf(stderr, "bad icmp6 checksum\n");
			return -1;
		}

		//analyzeICMP6(ptr, lest);
		//calcIP6Sum(ip6, ptr, len);
		
		analyzeICMP6(ptr, lest);
		return 1;
	}
	else if(ip6->ip6_nxt == IPPROTO_TCP){
		len = ntohs(ip6->ip6_plen);
		if(checkIP6Sum(ip6, ptr, len) == 0){
			fprintf(stderr, "bad tcp6 checksum\n");
			return -1;
		}
		analyzeTcp(ptr, lest);
		return 1;
	}
	else if(ip6->ip6_nxt == IPPROTO_UDP){
		len = ntohs(ip6->ip6_plen);
		if(checkIP6Sum(ip6, ptr, len) == 0){
			fprintf(stderr, "bad udp6 checksum\n");
			return -1;
		}
		analyzeUdp(ptr, lest);
		return 1;
	}
	return 0;
}

int analyzePacket2(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct ether_header *eh;

	ptr = data;	
	lest = size;

	if(lest < sizeof(struct ether_header)){
		fprintf(stderr, "lest(%d)<sizeof(struct ether_header)\n", lest);
		return -1;
	}
	eh = (struct ether_header *)ptr;
	ptr += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	if(ntohs(eh->ether_type) == ETHERTYPE_IPV6){
		fprintf(stderr, "Packet[%d]bytes\n", size);
		//printEtherHeader(eh, stdout);
		return analyzeIP6(ptr, lest);
	}
	return 0;
}

int analyzePacket(u_char *buf) {
	u_char *ptr;
	struct ether_header *eth;
	struct iphdr *ip;
	printEtherHeader(buf);
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

struct pseudo_ip6_hdr{
	struct in6_addr src;
	struct in6_addr dst;
	unsigned long plen;
	unsigned short dmy1;
	unsigned char dmy2;
	unsigned char nxt;
};

u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2){
	register u_int32_t sum;
	register u_int16_t *ptr;
	register int c;

	sum = 0;
	ptr = (u_int16_t *)data1;
	for(c=len1; c>1; c-=2){
		sum += (*ptr);
		if(sum&0x80000000){
			sum = (sum&0xFFFF)+(sum>>16);
		}
		ptr++;
	}
	if(c==1){
		u_int16_t val;
		val = ((*ptr)<<8)+(*data2);
		sum += val;
		if(sum&0x80000000){
			sum = (sum&0xFFFF)+(sum>>16);
		}
		ptr = (u_int16_t *)(data2+1);
		len2--;
	}
	else{
		ptr = (u_int16_t *)data2;
	}
	for(c=len2; c>1; c-=2){
		sum += (*ptr);
		if(sum&0x80000000){
			sum = (sum&0xFFFF)+(sum>>16);
		}
		ptr++;
	}
	if(c==1){
		u_int16_t val;
		val = 0;
		memcpy(&val, ptr, sizeof(u_int8_t));
		sum += val;
	}

	while(sum>>16){
		sum = (sum&0xFFFF)+(sum>>16);
	}

	return (~sum);
}

int calcIP6Sum(struct ip6_hdr *ip, unsigned char *data, int len, int itu){
	struct pseudo_ip6_hdr p_ip;
	unsigned short sum;

	memset(&p_ip, 0, sizeof(struct pseudo_ip6_hdr));
	
	memcpy(&p_ip.src, &ip->ip6_src, sizeof(struct in6_addr));
	memcpy(&p_ip.dst, &ip->ip6_dst, sizeof(struct in6_addr));
	p_ip.plen = ip->ip6_plen;
	p_ip.nxt = ip->ip6_nxt;

	switch(itu){
	case 0:
		//icmp
		{
		//scope
		u_char *zerodata;
		struct icmp6_hdr *zeroicmp;
		zerodata = data;
		zeroicmp = (struct icmp6_hdr *)zerodata;
		zeroicmp->icmp6_cksum = 0;

		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), zerodata, len);
		zeroicmp->icmp6_cksum = sum;
		}
		break;
	case 1:
		//tcp
		{
		u_char *zerodata;
		struct tcphdr *zerotcp;
		zerodata = data;
		zerotcp = (struct tcphdr *)zerodata;
		zerotcp->check = 0;

		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), zerodata, len);
		zerotcp->check = sum;
		}
		break;
	case 2:
		//udp
		{
		u_char *zerodata;
		struct udphdr *zeroudp;
		zerodata = data;
		zeroudp = (struct udphdr *)zerodata;
		zeroudp->check = 0;

		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), zerodata, len);
		zeroudp->check = sum;
		}
		break;
	}
	return 0;
}

int checkIP6Sum(struct ip6_hdr *ip, unsigned char *data, int len){
	struct pseudo_ip6_hdr p_ip;
	unsigned short sum;

	memset(&p_ip, 0, sizeof(struct pseudo_ip6_hdr));
	
	memcpy(&p_ip.src, &ip->ip6_src, sizeof(struct in6_addr));
	memcpy(&p_ip.dst, &ip->ip6_dst, sizeof(struct in6_addr));
	p_ip.plen = ip->ip6_plen;
	p_ip.nxt = ip->ip6_nxt;

	sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), data, len);
	if(sum == 0 || sum == 0xFFFF){
		return 1;
	}
	else{
		return 0;
	}
}

/*
u_int16_t checksumICMP6(struct in6_addr *src, struct in6_addr *dst, u_int32_t len, u_int16_t *data){  
	u_int32_t sum = 0;
	int i;

	//ipv6

	for(i=0; i<8; i++){
		sum += ntohs(src->s6_addr16[i]);
	}
	for(i=0; i<8; i++){
		sum += ntohs(dst->s6_addr16[i]);
	}

	sum += len >> 16;
	sum += len & 0x0000FFFF;  
	sum += IPPROTO_ICMPV6;

	//icmp

	for(i=0; i<len/2; i++){
		sum += ntohs(data[i]);
	}
	if(len%2)
		sum += *(u_int16_t *)&(data[i]);

	//sum = (sum & 0xffff) + (sum >> 16);
	//sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}  

void changeICMP6(u_char *buf){
	u_char *ptr;
	struct ip6_hdr *ip6_ptr;
	ptr = buf;
	ip6_ptr = (struct ip6_hdr *)ptr;
	if (ip6_ptr->ip6_nxt == 0x3A) {
		struct icmp6_hdr *icmp_ptr;
		ptr = (u_char *)ip6_ptr;
		ptr += sizeof(struct ip6_hdr);
		icmp_ptr = (struct icmp6_hdr *)ptr;
		printf("icmpchangeeeee---%x, ", ntohs(icmp_ptr->icmp6_cksum));
		icmp_ptr->icmp6_cksum = 0;
		icmp_ptr->icmp6_cksum = htons(checksumICMP6(&ip6_ptr->ip6_src,&ip6_ptr->ip6_dst,sizeof(struct icmp6_hdr),(u_int16_t *)icmp_ptr));
	printf("%x\n", ntohs(icmp_ptr->icmp6_cksum));
	}
}
*/

u_char* changeIP6SD(u_char *buf, int flag) {
	if(!IPV6_CHANGE)return buf;
	u_char *ptr;
	struct ip6_hdr *ip6_ptr;
	ptr = buf;
	ptr += sizeof(struct ether_header);
	ip6_ptr = (struct ip6_hdr *)ptr;
	//if(CHECKSUM == 1)
	//	changeICMP6((u_char *)ip6_ptr);
	int src_num = 2;
	u_int8_t src[3][16] = {
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x49, 0x81, 0x20, 0xa2,
		0x40, 0x6f, 0xc1, 0x44},
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x89, 0x64, 0x5e, 0xe3,
		0x82, 0xb9, 0x7f, 0x43},
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x27, 0xff,
		0xfe, 0xa9, 0xd6, 0xa1}};
	u_int8_t dst[16] = {
		0x20, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x10, 0x00};
	int i;
	printf("v6change---");
	if (flag == 0) {
		printf("out-");
		if(ip6_ptr->ip6_src.s6_addr[15] == dst[15]){
			printf("nat");
			for(i=0; i<16; i++){
				ip6_ptr->ip6_src.s6_addr[i] = src[src_num][i];
			}
		}
	}
	else {
		printf("in-");
		if(ip6_ptr->ip6_dst.s6_addr[15] == src[src_num][15]){
			printf("nat");
			for(i=0; i<16; i++){
				ip6_ptr->ip6_dst.s6_addr[i] = dst[i];
			}
		}
	}
	printf("\n");
	
	if(CHECKSUM == 1)
		calcIP6Sum(ip6_ptr, (u_char *)ip6_ptr + sizeof(struct ip6_hdr), ntohs(ip6_ptr->ip6_plen), 0);

	//printIP6Header((u_char *)buf + sizeof(struct ether_header));
//	if(CHECKSUM == 1)
//		changeICMP6((u_char *)ip6_ptr);
	return buf;
}

u_char* changeDest(u_char *buf, int flag) {
	if(!ETHER_CHANGE)return buf;
	struct ether_header *ptr;
	ptr = (struct ether_header *)buf;
	u_int8_t dhost[2][6] = {
		{ 0x08, 0x00, 0x27, 0xdc, 0x98, 0xe3 },
		{ 0x08, 0x00, 0x27, 0x58, 0x6b, 0xcc }
	};
	u_int8_t shost[2][6] = {
		{ 0x08, 0x00, 0x27, 0xa9, 0xd6, 0xa1 },
		{ 0x08, 0x00, 0x27, 0x05, 0x3c, 0x23 }
	};
	int i;
	for (i=0; i<6; i++) {
		ptr->ether_dhost[i] = dhost[flag][i];
		ptr->ether_shost[i] = shost[flag][i];
	}
	//printEtherHeader(buf);
	return (u_char *)ptr;
}

int main() {
	int i, size, flag;
	u_char buf[65535];
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
					printf("-----packet---------------\n");
					size = read(iflist[i].fd, buf, sizeof(buf));
					printf("recv from %s (%d octets)\n", dev[i], size);
					//flag = analyzePacket(buf);
					flag = analyzePacket2(buf, size);
					if (flag) {
						write(iflist[!i].fd, changeDest(changeIP6SD(buf, !i), !i), size);
						//write(iflist[!i].fd, changeDest(buf, !i), size);
						printf("\nsend to %s (%d octets)\n", dev[!i], size);
						analyzePacket2(buf, size);
					}
					printf("num: %d\n", packet_num++);
					printf("-----end------------------\n");
				}
			}
		}
	}
}
