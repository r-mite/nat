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

#include <ifaddrs.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <netdb.h>

#include <time.h>
#include <sys/time.h>

#define ETHER_CHANGE 1

#define IPV6_CHANGE 1
#define CHECKSUM 1
#define MOB_CHANGE 1

#define IF_NUM "eth4"
#define ALLCHECK 0
#define DIFF_CHECK 1

#define ALLMIN 35646
#define ALLMAX 35647

#define PRINT 0

int printIP6Header2(struct ip6_hdr *ip6, FILE *fp);
int analyzeIP6(u_char *data, int size);
u_int16_t chacksum2(u_char *data1, int len1, u_char *data2, int len2);



double get_time(void){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((double)(tv.tv_sec) * 1000 + (double)(tv.tv_usec) * 0.001);
}

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

/*
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
*/
/*
struct bu_hdr{
	u_int16_t seq;
	u_char ahlk;
	u_char reserve1;
	u_char reserve2;
	u_char reserve3;
	u_int16_t life;
};
*/


void getifipv6addr(struct in6_addr *ip6, const char *device){
	struct ifaddrs *if_list = NULL;
	struct ifaddrs *ifa = NULL;
	void *tmp = NULL;

	getifaddrs(&if_list);
	for(ifa = if_list; ifa != NULL; ifa = ifa->ifa_next){
		if(strcmp(ifa->ifa_name, device) == 0){
			if(!ifa->ifa_addr){
				continue;
			}else{
				if(ifa->ifa_addr->sa_family == AF_INET6){
					*ip6 = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
					break;
				}
			}
		}
	}
	freeifaddrs(if_list);
}


struct mobility_hdr{
	u_int8_t payload;
	u_int8_t len;
	u_int8_t type;
	u_int8_t reserve;
	u_int16_t check;
	union{
		u_int16_t data16[1];
		u_int8_t data8[2];
	}dataun;
};

#define mobility16 dataun.data16
#define mobility8 dataun.data8
#define MINLEN 8;

struct dstopt_hdr{
	u_int8_t nxt;
	u_int8_t len;
};

int printOption(struct mobility_hdr *mob, int len, FILE *fp){
	u_char *bp;
	bp = (u_char *)mob;
	fprintf(fp, "mobility_option--------------------\n");
	fprintf(fp, "type = %u,", bp[len]);
	len++;
	fprintf(fp, "length = %u\n", bp[len]);
	len += bp[len] + 1;
	fprintf(fp, "type = %u,", bp[len]);
	len++;
	fprintf(fp, "length = %u\n", bp[len]);
	len++;
	/*
	u_int16_t *coa;
	coa = (u_int16_t *)&bp[len];
	fprintf(fp, "length = %u\n", ntohs(*coa));
	*/
	int i;
	for(i=0; i<16; i++){
		fprintf(fp, "coa:%d = %02x,", i, bp[len++]);
		if(i % 4 == 3)fprintf(fp, "\n");
	}

	fprintf(fp, "type = %u,", bp[len]);
	len++;
	fprintf(fp, "length = %u,", bp[len]);
	len++;
	fprintf(fp, "optcode = %u,", bp[len]);
	len++;
	fprintf(fp, "pad = %u\n", bp[len]);
	len++;
	for(i=0; i<6; i++){
		fprintf(fp, "%02x,", bp[len++]);
	}
	fprintf(fp, "\n");

	fprintf(fp, "type = %u,", bp[len]);
	len++;
	fprintf(fp, "length = %u\n", bp[len]);
	len++;
	return 0;
}

int printBindingUpdate(struct mobility_hdr *mob, FILE *fp){
	u_char *bp;
	bp = (u_char *)mob;
	int len;
	fprintf(fp, "binding_update--------------------\n");
	fprintf(fp, "sequence = %u,", ntohs(mob->mobility16[0]));
	len = MINLEN;
	fprintf(fp, "flag = ");
	if(bp[len] & 0xf0)fprintf(fp, " ");
	if(bp[len] & 0x80)fprintf(fp, "A");
	if(bp[len] & 0x40)fprintf(fp, "H");
	if(bp[len] & 0x20)fprintf(fp, "L");
	if(bp[len] & 0x10)fprintf(fp, "K");
	fprintf(fp, ",");
	len++;
	u_int16_t *life;
	life = (u_int16_t *)&bp[len];
	fprintf(fp, "lifetime = %u\n", ntohs(*life));
	len += 3;
	return len;
}

int printMobility(struct mobility_hdr *mob, FILE *fp){
	fprintf(fp, "mobility--------------------\n");
	fprintf(fp, "pay = %u,", mob->payload);
	fprintf(fp, "length = %u,", mob->len);
	fprintf(fp, "type = %u,", mob->type);
	fprintf(fp, "reserve = %u,", mob->reserve);
	fprintf(fp, "check = %u\n", mob->check);
	return mob->len;
}

int printDstOpt(struct dstopt_hdr *opt, FILE *fp){
	fprintf(fp, "dstopt--------------------\n");
	fprintf(fp, "next = %u,", opt->nxt);
	fprintf(fp, "length = %u\n", opt->len);
	return 0;
}

/*
int printMsg(struct msghdr *msg, FILE *fp){
	struct sockaddr_in6 *in6;
	in6 = (struct sockaddr_in6 *)msg->msg_name;
	fprintf(fp, "msg--------------------\n");
	fprintf(fp, "msg_name = %s\n", ip6_ntoa(in6->sin6_addr));

	return 0;
}
*/

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
/*
int analyzeMsg(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct msghdr *msg;

	ptr = data;
	lest = size;

	msg = (struct msghdr *)ptr;
	ptr += sizeof(struct msghdr);
	lest -= sizeof(struct msghdr);

	printMsg(msg, stdout);

	return 0;
}
*/

/*
int analyzeBindingUpdate(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct bu_hdr *bu;

	ptr = data;
	lest = size;
	
	if(lest < sizeof(struct bu_hdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct br_hdr)\n", lest);
		return -1;
	}

	bu = (struct bu_hdr *)ptr;
	ptr += sizeof(struct bu_hdr);
	lest -= sizeof(struct bu_hdr);

	printBindingUpdate(bu, stdout);

	return 0;
}
*/

int analyzeMobility(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct mobility_hdr *mob;

	ptr = data;
	lest = size;
	
	if(lest < sizeof(struct mobility_hdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct mobility_hdr)\n", lest);
		return -1;
	}

	mob = (struct mobility_hdr *)ptr;
	ptr += sizeof(struct mobility_hdr);
	lest -= sizeof(struct mobility_hdr);

	int moblen;
	moblen = printMobility(mob, stdout);

	int optlen;
	optlen = printBindingUpdate(mob, stdout);
	printOption(mob, optlen, stdout);
	//analyzeBindingUpdate(mob, lest);

	return 0;
}

int analyzeDstOpt(u_char *data, int size){
	u_char *ptr;
	int lest;
	struct dstopt_hdr *opt;

	ptr = data;
	lest = size;
	
	if(lest < sizeof(struct dstopt_hdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct dstopt_hdr)\n", lest);
		return -1;
	}

	opt = (struct dstopt_hdr *)ptr;
	//ptr += sizeof(struct dstopt_hdr);
	//lest -= sizeof(struct dstopt_hdr);

	printDstOpt(opt, stdout);

	int dstoptlen = 0;
	dstoptlen = (int)((opt->len + 1) << 3);
	ptr += dstoptlen;
	lest -= dstoptlen;
	analyzeMobility(ptr, lest);

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
	
	/*
	if(tcphdr->rst == 1){
		return -1;
	}
	*/

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
	int err;

	ptr = data;
	lest = size;

	if(lest < sizeof(struct ip6_hdr)){
		fprintf(stderr, "lest(%d)<sizeof(struct ip6_hdr)\n", lest);
		return -1;
	}
	ip6 = (struct ip6_hdr *)ptr;
	ptr += sizeof(struct ip6_hdr);
	lest -= sizeof(struct ip6_hdr);

	if(ip6->ip6_dst.s6_addr[0] == 0xff ||
	ip6->ip6_dst.s6_addr[0] == 0xfe){
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
		err = analyzeTcp(ptr, lest);
		if(err == -1)return 0;
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
	else if(ip6->ip6_nxt == IPPROTO_DSTOPTS){
		//destination options for ipv6 = 60
		len = ntohs(ip6->ip6_plen);
		//u_char *optmob;
		//optmob = ptr;
		struct dstopt_hdr *opt;
		opt = (struct dstopt_hdr *)ptr;
		int optlen;
		optlen = (int)((opt->len + 1) << 3);
		//optmob += optlen;
		ptr += optlen;
		printf("len = %d, opt = %d, optlen = %d, moblen = %d\n", len, opt->len, optlen, len-optlen);
		
		if(checkIP6Sum(ip6, ptr, len) == 1){
			printf("checksum ok\n");
		}
		//else
		/*
		if(checkIP6Sum(ip6, ptr, len-optlen) == 1){
			printf("optmob len-opt checksum\n");
		}
		else{
			printf("bad checksum\n");
		}
		*/
		/*
		int i;
		for(i=0; i<4; i++){
			printf("%d: ", i);
			calcIP6Sum(ip6, ptr, len-optlen, IPPROTO_DSTOPTS, i);
			if(checkIP6Sum(ip6, ptr, len-optlen) == 1){
				printf("optmob len-opt checksum\n");
				break;
			}
		}
		printf("i = %d\n", i);
*/
		ptr -= optlen;
		analyzeDstOpt(ptr, lest);
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
		if(PRINT)fprintf(stderr, "Packet[%d]bytes\n", size);
		//printEtherHeader(eh, stdout);
		return analyzeIP6(ptr, lest);
	}
	return 0;
}

/*
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
		
		printIPHeader(ptr);
		if(ip->protocol==6){
		ptr+=((struct iphdr *)ptr)->ihl*4;
		printTcpHeader(ptr);
		}
		
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
*/

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


struct diff_hdr{
	struct in6_addr src;
	struct in6_addr dst;
	//unsigned long plen;
	//unsigned char nxt;
	unsigned char coa[16];
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

u_int16_t checksum3(u_int16_t s, u_char *data1, int len1, u_char *data2, int len2){
	register u_int32_t sum;
	register u_int16_t *ptr;
	register int c;

	//sum = 0;
	sum = ~s;
	ptr = (u_int16_t *)data1;
	printf("len1 = %d, ", len1);
	for(c=len1; c>1; c-=2){
		sum += (*ptr);
		if(sum&0x80000000){
			sum = (sum&0xFFFF)+(sum>>16);
		}
		ptr++;
	}
/*
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
	else{*/
		ptr = (u_int16_t *)data2;
	//}
	printf("len2 = %d\n", len2);
	for(c=len2; c>1; c-=2){
		sum += ~(*ptr) + 1;
		if(sum&0x80000000){
			sum = (sum&0xFFFF)+(sum>>16);
		}
		//sum++;
		ptr++;
	}

	while(sum>>16){
		sum = (sum&0xFFFF)+(sum>>16);
	}

	return (~sum);
}

int calcIP6Sum(struct ip6_hdr *ip, unsigned char *data, int len, int nxt, struct diff_hdr *before, struct diff_hdr *after){
	struct pseudo_ip6_hdr p_ip;
	unsigned short sum;

	memset(&p_ip, 0, sizeof(struct pseudo_ip6_hdr));
	
	memcpy(&p_ip.src, &ip->ip6_src, sizeof(struct in6_addr));
	memcpy(&p_ip.dst, &ip->ip6_dst, sizeof(struct in6_addr));
	p_ip.plen = ip->ip6_plen;
	p_ip.nxt = ip->ip6_nxt;

	u_char *zerodata;
	zerodata = data;

	switch(nxt){
	case IPPROTO_ICMPV6:
		{
		//scope
		struct icmp6_hdr *zeroicmp;
		zeroicmp = (struct icmp6_hdr *)zerodata;
		zeroicmp->icmp6_cksum = 0;
		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), zerodata, len);
		zeroicmp->icmp6_cksum = sum;
		}
		break;
	case IPPROTO_TCP:
		{
		struct tcphdr *zerotcp;
		zerotcp = (struct tcphdr *)zerodata;
		zerotcp->check = 0;
		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), zerodata, len);
		zerotcp->check = sum;
		}
		break;
	case IPPROTO_UDP:
		{
		struct udphdr *zeroudp;
		zeroudp = (struct udphdr *)zerodata;
		zeroudp->check = 0;
		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), zerodata, len);
		zeroudp->check = sum;
		}
		break;
	case IPPROTO_DSTOPTS:
		{
		p_ip.plen = htonl(len);
		p_ip.nxt = 135;
		//u_char *ptr;
		//ptr = zerodata;
		//struct dstopt_hdr *opt;
		//opt = (struct dstopt_hdr *)ptr;
		//opt = (struct dstopt_hdr *)zerodata;
		//zerodata += (int)((opt->len + 1) << 3);
		struct mobility_hdr *mob;
		mob = (struct mobility_hdr *)zerodata;
		if(!DIFF_CHECK){
			mob->check = 0;
			//mob->check = ~htons(16694);
			sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), zerodata, len);
			printf("calcsum1: %u - %04x\n", sum, sum);
			sum -= 16694;
			if(sum&0x80000000){
				sum = (sum&0xFFFF)+(sum>>16);
			}
			printf("calcsum2: %u - %04x\n", sum, sum);
			mob->check = sum;
		}
		else{
			//sum = ~(mob->check);
			sum = checksum3(mob->check, (unsigned char *)after, sizeof(struct diff_hdr), (unsigned char *)before, sizeof(struct diff_hdr));
			sum += ALLMIN;
			if(sum&0x80000000){
				sum = (sum&0xFFFF)+(sum>>16);
			}
/*
			sum += ~checksum2((unsigned char *)after, sizeof(struct diff_hdr), NULL, 0);
			if(sum&0x80000000){
				sum = (sum&0xFFFF)+(sum>>16);
			}*/
			/*sum = sum + mob->check;
			if(sum&0x80000000){
				sum = (sum&0xFFFF)+(sum>>16);
			}*/
			mob->check = sum;
		}
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


	//if(ip->ip6_nxt != IPPROTO_DSTOPTS){
		p_ip.plen = ip->ip6_plen;
		p_ip.nxt = ip->ip6_nxt;

		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), data, len);
		if(sum == 0 || sum == 0xFFFF){
			return 1;
		}
		printf("check: %u - %04x\n", sum, sum);
		return 0;
	/*}else{
		p_ip.plen = htonl(len);
		p_ip.nxt = 135;
		sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip6_hdr), data, len);
		if(sum == 0 || sum == 0xFFFF){
			printf("len-nxt-change\n");
			return 1;
		}
		printf("check: %u - %04x\n", sum, sum);
		return 0;
	}*/
	
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


u_char* changeSum(u_char *buf, int num) {
	u_char *ptr;
	struct ip6_hdr *ip6_ptr;
	ptr = buf;
	ptr += sizeof(struct ether_header);
	ip6_ptr = (struct ip6_hdr *)ptr;

	if(CHECKSUM){
		int len = ntohs(ip6_ptr->ip6_plen);
		ptr += sizeof(struct ip6_hdr);
		struct dstopt_hdr *opt;
		opt = (struct dstopt_hdr *)ptr;
		int optlen;
		optlen = (int)((opt->len + 1) << 3);
		ptr += optlen;
		struct mobility_hdr *mob;
		mob = (struct mobility_hdr *)ptr;
		u_int32_t sum = mob->check;
		if(num == ALLMIN)
		sum += num;
		else
		sum++;
		if(sum&0x80000000){
			sum = (sum&0xFFFF)+(sum>>16);
		}
		mob->check = (u_int16_t)sum;
	}
	return buf;
}

void changeMobility(u_char *buf, struct diff_hdr *before, struct diff_hdr *after){
	if(!MOB_CHANGE)return;
	u_char *ptr;
	struct ip6_hdr *ip6_ptr;
	ptr = buf;
	ptr += sizeof(struct ether_header);
	ip6_ptr = (struct ip6_hdr *)ptr;

	if(ip6_ptr->ip6_nxt == IPPROTO_DSTOPTS){
		ptr += sizeof(struct ip6_hdr);
		struct dstopt_hdr *opt;
		opt = (struct dstopt_hdr *)ptr;
		ptr += (int)((opt->len + 1) << 3);
		int binding = 12;
		int option = 4;
		ptr += binding + option;

		struct in6_addr ip6;
		getifipv6addr(&ip6, IF_NUM);

		int i;
		for(i=0; i<16; i++){
			before->coa[i] = *ptr;
			*ptr = ip6.s6_addr[i];
			after->coa[i] = *ptr;
			ptr++;
		}
	}
}

void changeIP6SD(u_char *buf, int flag) {
	struct diff_hdr before;
	struct diff_hdr after;
	
	memset(&before, 0, sizeof(struct diff_hdr));
	memset(&after, 0, sizeof(struct diff_hdr));

	changeMobility(buf, &before, &after);
	//if(!IPV6_CHANGE)return;
	u_char *ptr;
	struct ip6_hdr *ip6_ptr;
	ptr = buf;
	ptr += sizeof(struct ether_header);
	ip6_ptr = (struct ip6_hdr *)ptr;
	int i;
	for(i=0; i<16; i++){
		before.src.s6_addr[i] = ip6_ptr->ip6_src.s6_addr[i];
		before.dst.s6_addr[i] = ip6_ptr->ip6_dst.s6_addr[i];
		after.src.s6_addr[i] = ip6_ptr->ip6_src.s6_addr[i];
		after.dst.s6_addr[i] = ip6_ptr->ip6_dst.s6_addr[i];
	}

	if(!IPV6_CHANGE && CHECKSUM){
		/*for(i=0; i<16; i++){
			after.src.s6_addr[i] = ip6_ptr->ip6_src.s6_addr[i];
			after.dst.s6_addr[i] = ip6_ptr->ip6_dst.s6_addr[i];
		}*/
		int len = ntohs(ip6_ptr->ip6_plen);
		ptr += sizeof(struct ip6_hdr);
		struct dstopt_hdr *opt;
		opt = (struct dstopt_hdr *)ptr;
		int optlen;
		optlen = (int)((opt->len + 1) << 3);
		ptr += optlen;
		//calcIP6Sum(ip6_ptr, (u_char *)ip6_ptr + sizeof(struct ip6_hdr), ntohs(ip6_ptr->ip6_plen), ip6_ptr->ip6_nxt, 3);
		calcIP6Sum(ip6_ptr, ptr, len - optlen, ip6_ptr->ip6_nxt, &before, &after);
	}

	if(!IPV6_CHANGE)return;

	int src_num = 0;
	u_int8_t src[3][16] = {
		{0x30, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x10, 0x00},
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x27, 0xff,
		0xfe, 0xa9, 0xd6, 0xa2},
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x27, 0xff,
		0xfe, 0xa9, 0xd6, 0xa1}};
	int dst_num = 1;
	u_int8_t dst[3][16] = {
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x27, 0xff,
		0xfe, 0xdc, 0x98, 0xe3},
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x27, 0xff,
		0xfe, 0xa9, 0xd6, 0xa2},
		{0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x0a, 0x00, 0x27, 0xff,
		0xfe, 0xa9, 0xd6, 0xa1}};

	printf("v6change---");
	if (flag == 0) {
		printf("in-");
		//自分宛
		if(ip6_ptr->ip6_dst.s6_addr[15] == dst[1][15]){
			printf("nat");
			for(i=0; i<16; i++){
				//my_private
				ip6_ptr->ip6_src.s6_addr[i] = src[0][i];
				//son
				ip6_ptr->ip6_dst.s6_addr[i] = dst[0][i];
			}
		}
	}
	else {
		printf("out-");
		//if(ip6_ptr->ip6_dst.s6_addr[15] == src[src_num][15]){
			printf("nat");
			for(i=0; i<16; i++){
				//my_gloval
				ip6_ptr->ip6_src.s6_addr[i] = src[2][i];
				after.src.s6_addr[i] = src[2][i];
				//ip6_ptr->ip6_dst.s6_addr[i] = dst[][i];
			}
		//}
	}
	printf("\n");
	/*for(i=0; i<16; i++){
		after.src.s6_addr[i] = ip6_ptr->ip6_src.s6_addr[i];
		after.dst.s6_addr[i] = ip6_ptr->ip6_dst.s6_addr[i];
	}*/
/*	
	if(CHECKSUM){
		calcIP6Sum(ip6_ptr, (u_char *)ip6_ptr + sizeof(struct ip6_hdr), ntohs(ip6_ptr->ip6_plen), ip6_ptr->ip6_nxt, 0);
	}
*/
	if(CHECKSUM){
		int len = ntohs(ip6_ptr->ip6_plen);
		ptr += sizeof(struct ip6_hdr);
		struct dstopt_hdr *opt;
		opt = (struct dstopt_hdr *)ptr;
		int optlen;
		optlen = (int)((opt->len + 1) << 3);
		ptr += optlen;
		if(ip6_ptr->ip6_nxt != IPPROTO_DSTOPTS){
			calcIP6Sum(ip6_ptr, (u_char *)ip6_ptr + sizeof(struct ip6_hdr), ntohs(ip6_ptr->ip6_plen), ip6_ptr->ip6_nxt, &before, &after);
		}
		else{
			calcIP6Sum(ip6_ptr, ptr, len - optlen, ip6_ptr->ip6_nxt, &before, &after);
		}
	}
}

u_char* changeDest(u_char *buf, int flag) {
	changeIP6SD(buf, flag);
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

	double d0, d1;

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
					if(PRINT)printf("-----packet---------------\n");
					size = read(iflist[i].fd, buf, sizeof(buf));
					d0 = get_time();
					if(PRINT)printf("recv from %s (%d octets)\n", dev[i], size);
					//flag = analyzePacket(buf);
					flag = analyzePacket2(buf, size);
					if (flag) {
						printf("\nsend to %s (%d octets)\n", dev[!i], size);
						if(!ALLCHECK){
							write(iflist[!i].fd, changeDest(buf, !i), size);
							analyzePacket2(buf, size);
						}
						else{
							u_char *buff = changeDest(buf, !i);
							int j;
							for(j=ALLMIN; j<ALLMAX; j++){
								write(iflist[!i].fd, changeSum(buff, j), size);
							}
							analyzePacket2(buff, size);
						}
						d1 = get_time();
						//printf("\nsend to %s (%d octets)\n", dev[!i], size);
						//analyzePacket2(buff, size);
						printf("\ntime: %fms\n", d1 - d0);
					}
					if(PRINT){
						printf("num: %d\n", packet_num++);
						printf("-----end------------------\n");
					}
					else
						printf(".");
				}
			}
		}
	}
}
