#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_ether.h>
#include <arpa/inet.h>

#include "libl2pkt.h"
#include "toeplitz_hash.h"
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define PROTO_HAS_PORT(p)	(((p) == IPPROTO_TCP) || ((p) == IPPROTO_UDP))

#define	MAXFRAMESIZE	(1024 * 64)
#define	MAXPACKETSIZE	(MAXFRAMESIZE - sizeof(struct ether_header))


int bpf_open(const char *);

static int opt_v;
static int opt_bad_ip4csum = 0;
static int opt_bad_l4csum = 0;
static struct l2pkt *l2pkt;
static int vlanid = -1;


struct option long_options[] = {
	{ "src",		required_argument,	NULL, 0 },
	{ "dst",		required_argument,	NULL, 0 },
	{ "proto",		required_argument,	NULL, 0 },
	{ "ttl",		required_argument,	NULL, 0 },
	{ "tos",		required_argument,	NULL, 0 },
	{ "fragoff",		required_argument,	NULL, 0 },
	{ "srcport",		required_argument,	NULL, 0 },
	{ "dstport",		required_argument,	NULL, 0 },
	{ "ip4csum",		required_argument,	NULL, 0 },
	{ "bad-ip4csum",	no_argument,		&opt_bad_ip4csum, 1 },
	{ "l4csum",		required_argument,	NULL, 0 },
	{ "bad-l4csum",		no_argument,		&opt_bad_l4csum, 1 },
	{ "rsshash2",		required_argument,	NULL, 0 },
	{ "rsshash4",		required_argument,	NULL, 0 },
	{ "tcpflags",		required_argument,	NULL, 0 },
	{ 0, 0, 0, 0 }
};

static void
usage()
{
	fprintf(stderr, "usage: l2pkt [option]\n");
	fprintf(stderr, "	-D <etheraddr>		destination mac address (default: ff:ff:ff:ff:ff:ff)\n");
	fprintf(stderr, "	-S <etheraddr>		source mac address (default: own addr)\n");
	fprintf(stderr, "	-V <vid>		VLAN ID\n");
	fprintf(stderr, "	-X			dump generated packet\n");
//	fprintf(stderr, "	-a			build arp query packet\n");
	fprintf(stderr, "	-4			build IPv4 packet\n");
	fprintf(stderr, "	-6			build IPv6 packet\n");
	fprintf(stderr, "	--src <addr>		source address\n");
	fprintf(stderr, "	--dst <addr>		destination address\n");
	fprintf(stderr, "	--proto <proto>		protocol\n");
	fprintf(stderr, "	--tos <tos>		type of service (default: 0)\n");
	fprintf(stderr, "	--ttl <ttl>		TTL (default: 0)\n");
	fprintf(stderr, "	--fragoff <offset>	fragment offset (default: 0)\n");
	fprintf(stderr, "	--srcport <port>	source port\n");
	fprintf(stderr, "	--dstport <port>	destination port\n");
	fprintf(stderr, "	--ip4csum <sum>		specify IPv4 checksum\n"
			"				(adjusting by modifying ip_id)\n");
	fprintf(stderr, "	--bad-ip4csum		don't adjust IPv4 checksum\n");
	fprintf(stderr, "	--l4csum <sum>		specify L4 checksum (TCP,UDP,ICMP)\n"
			"				(adjusting by modifying last 2 bytes of payload)\n");
	fprintf(stderr, "	--bad-l4csum		don't adjust L4 checksum\n");
	fprintf(stderr, "	--rsshash2 <idx>/<mod>	specify 2-tuple rsshash by modifying source addr\n");
	fprintf(stderr, "	--rsshash4 <idx>/<mod>	specify 4-tuple rsshash by modifying source/dest port\n");
	fprintf(stderr, "	--tcpflags [FSRPAUEC-]	specify TCP flags\n");
	fprintf(stderr, "	-T			fill 16byte timestamp string in the end of packet\n");
	fprintf(stderr, "	-i <interface>		output interface\n");
	fprintf(stderr, "	-n <npacket>		output N packets (default: 1)\n");
	fprintf(stderr, "	-r			fill a packet with random data\n");
	fprintf(stderr, "	-R <seed>		specify random seed (default: pid)\n");
	fprintf(stderr, "	-f <framesize>		L2 frame size (default: 60 or (packetsize + 14))\n");
	fprintf(stderr, "	-s <packetsize>		L3 packet size (default: 46 or (framesize - 14))\n");

	fprintf(stderr, "	-t <ethertype>		ethernet type (default: 0x88b5)\n");
	fprintf(stderr, "	-v			verbose\n");
	exit(1);
}

static in_addr_t
inaddr(const char *s)
{
	struct in_addr in;
	inet_aton(s, &in);
	return in.s_addr;
}

static char *
strin4addr(struct in_addr *in)
{
	static int idx = 0;
	static char buf[8][INET_ADDRSTRLEN];
	char *p;

	idx = (idx + 1) % 8;
	p = buf[idx];

	inet_ntop(AF_INET, in, p, sizeof(buf[0]));
	return p;
}

static char *
strin6addr(struct in6_addr *in6)
{
	static int idx = 0;
	static char buf[8][INET6_ADDRSTRLEN];
	char *p;

	idx = (idx + 1) % 8;
	p = buf[idx];

	inet_ntop(AF_INET6, in6, p, sizeof(buf[0]));
	return p;
}

static char *
straddr(int af, const void * restrict addr)
{
	switch (af) {
	case AF_INET:
		return strin4addr((struct in_addr *)addr);
	case AF_INET6:
		return strin6addr((struct in6_addr *)addr);
	default:
		break;
	}
	return NULL;
}

static int
parsenum(const char *str, int *v, long long min, long long max)
{
	long long x;
	char *ep = NULL;
	int base = 10;

	if (strncasecmp(str, "0x", 2) == 0) {
		base = 16;
		str += 2;
	}

	x = strtoll(str, &ep, base);
	if (ep == str)
		return -1;
	if (x < min)
		return -2;
	if (x > max)
		return -3;

	*v = x;
	return 0;
}

int
main(int argc, char *argv[])
{
	struct ether_addr *eaddr, eaddr_src, eaddr_dst;
	int ether_header_size;
	ssize_t r;
	int npacket = 1;
	unsigned long nsend;
	int bpf_fd, ch;
	int bpf_hdrcmplt = 0;
	int opt_timestamp = 0;
	int opt_randseed = getpid();
	int opt_random = 0;
	int opt_protocol = -1;
	int opt_tos = -1;
	int opt_ttl = -1;
	uint32_t opt_rsshash2idx = 0, opt_rsshash2mod = 0;
	uint32_t opt_rsshash4idx = 0, opt_rsshash4mod = 0;
	bool opt_ip4src = false;
	bool opt_ip4dst = false;
	struct in_addr ip4src, ip4dst;
	bool opt_ip6src = false;
	bool opt_ip6dst = false;
	struct in6_addr ip6src, ip6dst;
	bool opt_srcport = false;
	bool opt_dstport = false;
	int opt_hexdump = 0;
	int opt_fragoff = 0;
	int opt_ip4csum = -1;
	int opt_l4csum = -1;
	int srcport, dstport;
	int i;
	int opt_family = 0;
	int packetsize = -1;
	int framesize = -1;
	int ethertype = 0x88b5;	/* IEEE Std 802 - Local Experimental Ethertype */
	char *ifname = NULL;
	int opt_tcpflags = -1;

	memset(&eaddr_src, 0x00, sizeof(eaddr_src));
	memset(&eaddr_dst, 0xff, sizeof(eaddr_dst));

	while ((ch = getopt_long(argc, argv, "46D:R:S:TXf:i:t:n:rs:V:v", long_options, NULL)) != -1) {
		switch (ch) {
		case 0:
			if (optind < 2) {
				usage();
			} else {
				const char *optname;
				optname = argv[optind - 2];

				if (optarg == NULL)
					break;

//				printf("DEBUG: longopt: optind=%d, %s = %s\n", optind, optname, optarg);

				if (strcmp("--proto", optname) == 0) {
					struct protoent *pe;
					pe = getprotobyname(optarg);
					if (pe != NULL) {
						opt_protocol = pe->p_proto;
					} else {
						if (parsenum(optarg, &opt_protocol, 0, 255) != 0)
							errx(1, "illegal protocol: %s", optarg);
					}
					endprotoent();
				} else if (strcmp("--src", optname) == 0) {
					if (inet_pton(AF_INET6, optarg, &ip6src) == 1)
						opt_ip6src = true;
					else if (inet_pton(AF_INET, optarg, &ip4src) == 1)
						opt_ip4src = true;
					else
						errx(1, "invalid address: %s", optarg);
				} else if (strcmp("--dst", optname) == 0) {
					if (inet_pton(AF_INET6, optarg, &ip6dst) == 1)
						opt_ip6dst = true;
					else if (inet_pton(AF_INET, optarg, &ip4dst) == 1)
						opt_ip4dst = true;
					else
						errx(1, "invalid address: %s", optarg);
				} else if (strcmp("--tos", optname) == 0) {
					if (parsenum(optarg, &opt_tos, 0, 0xff) != 0)
						errx(1, "invalid tos: %s", optarg);
				} else if (strcmp("--ttl", optname) == 0) {
					if (parsenum(optarg, &opt_ttl, 0, 0xff) != 0)
						errx(1, "invalid ttl: %s", optarg);
				} else if (strcmp("--srcport", optname) == 0) {
					opt_srcport = true;
					if (parsenum(optarg, &srcport, 0, 65535) != 0)
						errx(1, "invalid srcport: %s", optarg);
				} else if (strcmp("--dstport", optname) == 0) {
					opt_dstport = true;
					if (parsenum(optarg, &dstport, 0, 65535) != 0)
						errx(1, "invalid dstport: %s", optarg);
				} else if (strcmp("--fragoff", optname) == 0) {
					if (parsenum(optarg, &opt_fragoff, 0, 0xffff) != 0)
						errx(1, "invalid fragment offset: %s", optarg);
				} else if (strcmp("--ip4csum", optname) == 0) {
					if (parsenum(optarg, &opt_ip4csum, 0, 0xffff) != 0)
						errx(1, "invalid checksum: %s", optarg);
				} else if (strcmp("--l4csum", optname) == 0) {
					if (parsenum(optarg, &opt_l4csum, 0, 0xffff) != 0)
						errx(1, "invalid checksum: %s", optarg);
				} else if (strcmp("--rsshash2", optname) == 0) {
					char *p = strdup(optarg);
					char *q = strchr(p, '/');
					if (q == NULL)
						errx(1, "invalid rsshash. e.g.) \"3/16\": %s", optarg);
					*q++ = '\0';
					if (parsenum(p, &opt_rsshash2idx, 0, 0xffffffff) != 0)
						errx(1, "invalid rsshash: %s", p);
					if (parsenum(q, &opt_rsshash2mod, 0, 0xffffffff) != 0)
						errx(1, "invalid rsshash: %s", q);
					if (opt_rsshash2idx >= opt_rsshash2mod)
						errx(1, "rsshash <idx> less than <mod>: %s", optarg);

				} else if (strcmp("--rsshash4", optname) == 0) {
					char *p = strdup(optarg);
					char *q = strchr(p, '/');
					if (q == NULL)
						errx(1, "invalid rsshash. e.g.) \"3/16\": %s", optarg);
					*q++ = '\0';
					if (parsenum(p, &opt_rsshash4idx, 0, 0xffffffff) != 0)
						errx(1, "invalid rsshash: %s", p);
					if (parsenum(q, &opt_rsshash4mod, 0, 0xffffffff) != 0)
						errx(1, "invalid rsshash: %s", q);
					if (opt_rsshash4idx >= opt_rsshash4mod)
						errx(1, "rsshash <idx> less than <mod>: %s", optarg);

				} else if (strcmp("--tcpflags", optname) == 0) {
					char *p = optarg;
					opt_tcpflags = 0;
					for (; *p != '\0'; p++) {
						switch (*p) {
						case 'F':
							opt_tcpflags |= TH_FIN;
							break;
						case 'S':
							opt_tcpflags |= TH_SYN;
							break;
						case 'R':
							opt_tcpflags |= TH_RST;
							break;
						case 'P':
							opt_tcpflags |= TH_PUSH;
							break;
						case 'A':
						case '.':
							opt_tcpflags |= TH_ACK;
							break;
						case 'U':
							opt_tcpflags |= TH_URG;
							break;
						case 'E':
							opt_tcpflags |= TH_ECE;
							break;
						case 'C':
							opt_tcpflags |= TH_CWR;
							break;
						case '-':
						case '0':
							break;
						default:
							errx(1, "available tcpflags are 'FSRPAUEC': %s", optarg);
						}
					}
				} else {
					errx(1, "unknown option: %s", optname);
				}
			}
			break;

		case '4':
			opt_family = AF_INET;
			ethertype = ETHERTYPE_IP;
			break;
		case '6':
			opt_family = AF_INET6;
			ethertype = ETHERTYPE_IPV6;
			break;

		case 'D':
		case 'S':
			eaddr = ether_aton(optarg);
			if (eaddr == NULL) {
				errx(1, "illegal mac address: %s", optarg);
			}
			if (ch == 'D') {
				memcpy(&eaddr_dst, eaddr, sizeof(eaddr));
			} else if (ch == 'S') {
				bpf_hdrcmplt = 1;
				memcpy(&eaddr_src, eaddr, sizeof(eaddr));
			}
			break;
		case 'T':
			opt_timestamp++;
			break;
		case 'X':
			opt_hexdump++;
			break;
		case 'f':
			if (parsenum(optarg, &framesize, 0, MAXFRAMESIZE) != 0)
				errx(1, "illegal framesize: %s", optarg);
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'n':
			if (parsenum(optarg, &npacket, 0, INT_MAX) != 0)
				errx(1, "illegal number: %s", optarg);
			break;
		case 'R':
			if (parsenum(optarg, &opt_randseed, 0, 0xffffffff) != 0)
				errx(1, "illegal number: %s", optarg);
			break;
		case 'r':
			opt_random = 1;
			break;
		case 's':
			if (parsenum(optarg, &packetsize, 0, MAXPACKETSIZE) != 0)
				errx(1, "illegal packetsize: %s", optarg);
			break;
		case 't':
			if (parsenum(optarg, &ethertype, 0, 0xffff) != 0)
				errx(1, "illegal ethertype: %s", optarg);
			break;
		case 'v':
			opt_v++;
			break;
		case 'V':
			if (parsenum(optarg, &vlanid, 0, 65535) != 0)
				errx(1, "illegal vlan id: %s", optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ((argc != 0) || (ifname == NULL))
		usage();


	ether_header_size = sizeof(struct ether_header);
	if (vlanid != -1)
		ether_header_size += 4;

	if ((framesize == -1) && (packetsize == -1)) {
		packetsize = 46;
		framesize = packetsize + ether_header_size;
	} else if (framesize == -1) {
		framesize = packetsize + ether_header_size;
	} else if (packetsize == -1) {
		packetsize = framesize - ether_header_size;
	} else if (framesize < packetsize + ether_header_size) {
		fprintf(stderr, "Warning: framesize (%d) is greater than packetsize (%d) + L2 header size (%d)\n",
		    framesize, packetsize, ether_header_size);
	}


	bpf_fd = bpf_open(ifname);
	if (bpf_fd < 0)
		exit(2);

	if (bpf_hdrcmplt) {
		ioctl(bpf_fd, BIOCSHDRCMPLT, &bpf_hdrcmplt);
	}

	l2pkt = l2pkt_create(MAXFRAMESIZE);
	if (l2pkt == NULL) {
		errx(3, "cannot create packet buffer");
	}

	if (opt_random) {
		if (opt_v)
			printf("srand(%d)\n", opt_randseed);
		srand(opt_randseed);
		char *p = L2PKT_L2BUF(l2pkt);
		for (i = 0; i < MAXFRAMESIZE; i++) {
			p[i] = rand();
		}
	}

	l2pkt_setframesize(l2pkt, framesize);
	if (vlanid != -1)
		l2pkt_ethpkt_vlan(l2pkt, vlanid);
	l2pkt_ethpkt_type(l2pkt, ethertype);
	l2pkt_ethpkt_src(l2pkt, &eaddr_src);
	l2pkt_ethpkt_dst(l2pkt, &eaddr_dst);

	if (opt_timestamp) {
		struct timeval tv;
		struct tm *tm;
		char buf[32];

		gettimeofday(&tv, 0);
		tm = localtime(&tv.tv_sec);

		/*
		 * "0123456789ABCDEF"
		 * "[23:59:59.99999]"
		 */
#define TIMESTAMPSTRSIZE 16
		snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%05d]",
		    tm->tm_hour, tm->tm_min, tm->tm_sec,
		    tv.tv_usec / 10);

		/* XXX */
		char *p = L2PKT_L2BUF(l2pkt) + L2PKT_L2SIZE(l2pkt);
		for (; opt_timestamp > 0; opt_timestamp--) {
			p -= TIMESTAMPSTRSIZE;
			if (p <= L2PKT_L2BUF(l2pkt))
				break;
			memcpy(p, buf, TIMESTAMPSTRSIZE);
		}
	}

	/* build packet (per packet parameter) */
	if (opt_family == AF_INET) {
		switch (opt_protocol) {
		case IPPROTO_UDP:
			l2pkt_ip4_udp_template(l2pkt, packetsize - sizeof(struct ip));
			break;
		case IPPROTO_TCP:
			l2pkt_ip4_tcp_template(l2pkt, packetsize - sizeof(struct ip));
			break;
		case IPPROTO_ICMP:
			l2pkt_ip4_icmp_template(l2pkt, packetsize - sizeof(struct ip));
			break;
		default:
			if (opt_protocol == -1) {
				if (opt_random)
					opt_protocol = rand();
				else
					opt_protocol = IPPROTO_IP;
			}
			l2pkt_ip4_proto_template(l2pkt, opt_protocol, packetsize - sizeof(struct ip));
			break;
		}

#if 0
		// XXX:DEBUG
		l2pkt_ip4_off(l2pkt, 1234);
		l2pkt_ip4_id(l2pkt, 0x8765);
#endif
		if (opt_tos >= 0)
			l2pkt_ip4_tos(l2pkt, opt_tos);

		if (opt_ttl >= 0)
			l2pkt_ip4_ttl(l2pkt, opt_ttl);

		if (opt_ip4src)
			l2pkt_ip4_src(l2pkt, ip4src.s_addr);
		if (opt_ip4dst)
			l2pkt_ip4_dst(l2pkt, ip4dst.s_addr);

		if (opt_fragoff != 0) {
			l2pkt_ip4_off(l2pkt, opt_fragoff);
		}

	} else if (opt_family == AF_INET6) {
		switch (opt_protocol) {
		case IPPROTO_UDP:
			l2pkt_ip6_udp_template(l2pkt, packetsize - sizeof(struct ip6_hdr));
			break;
		case IPPROTO_TCP:
			l2pkt_ip6_tcp_template(l2pkt, packetsize - sizeof(struct ip6_hdr));
			break;
		case IPPROTO_ICMPV6:
			l2pkt_ip6_icmp6_template(l2pkt, packetsize - sizeof(struct ip6_hdr));
			break;
		default:
			if (opt_protocol == -1) {
				if (opt_random)
					opt_protocol = rand();
				else
					opt_protocol = IPPROTO_IP;
			}
			l2pkt_ip6_proto_template(l2pkt, opt_protocol, packetsize - sizeof(struct ip6_hdr));
			break;
		}

//		if (opt_ttl > 0)
//			l2pkt_ip6_ttl(l2pkt, opt_ttl);

		if (opt_ip6src)
			l2pkt_ip6_src(l2pkt, &ip6src);
		if (opt_ip6dst)
			l2pkt_ip6_dst(l2pkt, &ip6dst);

		if (opt_fragoff != 0) {
			/*
			 * L3 header will be incresed.
			 * L4 size will be decrease sizeof(ip6_frag) bytes
			 */
			l2pkt_ip6_off(l2pkt, opt_fragoff, false, 0x1234);
		}
	}

	if (opt_srcport)
		l2pkt_srcport(l2pkt, srcport);
	if (opt_dstport)
		l2pkt_dstport(l2pkt, dstport);

	if (opt_tcpflags >= 0 && opt_protocol == IPPROTO_TCP)
		l2pkt_tcpflags(l2pkt, opt_tcpflags);

	if (opt_rsshash2mod | opt_rsshash4mod) {
		union {
			struct in_addr addr4;
			struct in6_addr addr6;
		} src, dst;
		size_t addrlen = sizeof(struct in_addr);
		int af = opt_family;
		uint32_t hash, i, j;
		uint16_t sport, dport;

		if (opt_family == AF_INET6)
			addrlen = sizeof(struct in6_addr);

		if (opt_rsshash2mod) {

			l2pkt_extract(l2pkt);
			memcpy(&src, &l2pkt->info.src, addrlen);
			memcpy(&dst, &l2pkt->info.dst, addrlen);

			for (i = 0; ; i++) {
				hash = toeplitz_hash(rsskey, sizeof(rsskey), 
				    &src, addrlen,
				    &dst, addrlen,
				    NULL);
				if ((hash % opt_rsshash2mod) == opt_rsshash2idx) {
					if (opt_v) {
						fprintf(stderr, "Found rsshash2(%s %s) = 0x%08x, (0x%08x %% 0x%08x) == 0x%08x   \n",
						    straddr(af, &src), straddr(af, &dst),
						    hash, hash, opt_rsshash2mod, opt_rsshash2idx);
					}
					break;
				}
				if (opt_v & ((i & 255) == 0)) {
					fprintf(stderr, "checking rsshash2(%s %s) = 0x%08x, (0x%08x %% 0x%08x) == 0x%08x   \r",
					    straddr(af, &src), straddr(af, &dst),
					    hash, hash, opt_rsshash2mod, opt_rsshash2idx);
				}

				if (af == AF_INET)
					src.addr4.s_addr = htonl(ntohl(src.addr4.s_addr) + 1);
				else
					src.addr6.s6_addr32[3] = htonl(ntohl(src.addr6.s6_addr32[3]) + 1);
			}

			if (af == AF_INET)
				l2pkt_ip4_src(l2pkt, src.addr4.s_addr);
			else
				l2pkt_ip6_src(l2pkt, (struct in6_addr *)&src);
		}

		if (opt_rsshash4mod) {
			if (!PROTO_HAS_PORT(opt_protocol))
				errx(1, "--rsshash4 requires --proto tcp or --proto udp");

			l2pkt_extract(l2pkt);
			memcpy(&src, &l2pkt->info.src, addrlen);
			memcpy(&dst, &l2pkt->info.dst, addrlen);
			sport = l2pkt->info.sport;
			dport = l2pkt->info.dport;

			for (j = 0; j < 65536; j++) {
				for (i = 0; i < 65536; i++) {
					hash = toeplitz_hash(rsskey, sizeof(rsskey), 
					    &src, addrlen,
					    &dst, addrlen,
					    &sport, sizeof(sport),
					    &dport, sizeof(dport),
					    NULL);
					if ((hash % opt_rsshash4mod) == opt_rsshash4idx) {
						if (opt_v) {
							fprintf(stderr, "Found rsshash4(%s %s %d %d) = 0x%08x, (0x%08x %% 0x%08x) == 0x%08x     \n",
							    straddr(af, &src), straddr(af, &dst), ntohs(sport), ntohs(dport),
							    hash, hash, opt_rsshash4mod, opt_rsshash4idx);
						}
						goto found;
					}
					if (opt_v & ((i & 255) == 0)) {
						fprintf(stderr, "checking rsshash4(%s %s %d %d) = 0x%08x, (0x%08x %% 0x%08x) != 0x%08x     \r",
						    straddr(af, &src), straddr(af, &dst), ntohs(sport), ntohs(dport),
						    hash, hash, opt_rsshash4mod, opt_rsshash4idx);
					}
					sport = htons(ntohs(sport) + 1);
				}
				dport = htons(ntohs(dport) + 1);
			}
			fprintf(stderr, "\n");
			err(5, "tupple4: %08x/%08x hash not found\n", opt_rsshash4mod, opt_rsshash4idx);
 found:
			l2pkt_srcport(l2pkt, ntohs(sport));
			l2pkt_dstport(l2pkt, ntohs(dport));
		}
	}

	if (opt_l4csum >= 0) {
		int l4hdrlen = l2pkt_getl4hdrlength(l2pkt);
		int l4len = l2pkt_getl4length(l2pkt);
		if ((l4len - l4hdrlen) < sizeof(uint16_t))
			errx(5, "no space in L4 payload for adjusting checksum. increase packetsize");

		if (opt_bad_l4csum || (opt_protocol == IPPROTO_UDP && opt_l4csum == 0)) {
			uint16_t ucsum = htons(opt_l4csum);
			int l4csumoff = l2pkt_getl4csumoffset(l2pkt);
			l2pkt_l4write_raw(l2pkt, l4csumoff, (char *)&ucsum, 2);
		} else {
			/* write a checksum you want as payload data with adjusting checksum */
			uint16_t ucsum = htons(opt_l4csum);

			l2pkt_l4write(l2pkt, l4len - 2, (char *)&ucsum, 2);

			uint16_t ocsum;
			l2pkt_l4read(l2pkt, l2pkt_getl4csumoffset(l2pkt), (char *)&ocsum, 2);

			/* swap l4csum and payload data */
			int l4csumoff = l2pkt_getl4csumoffset(l2pkt);
			l2pkt_l4write_raw(l2pkt, l4csumoff, (char *)&ucsum, 2);
			l2pkt_l4write_raw(l2pkt, l4len - 2, (char *)&ocsum, 2);
		}
	}

	if ((opt_ip4csum >= 0) && (opt_family == AF_INET)) {
		if (opt_bad_ip4csum) {
			struct ip *ip = (struct ip *)L2PKT_L3BUF(l2pkt);
			ip->ip_sum = htons(opt_ip4csum);
		} else {
			struct ip *ip = (struct ip *)L2PKT_L3BUF(l2pkt);
			l2pkt_ip4_id(l2pkt, opt_ip4csum);
			uint16_t tmp = ip->ip_id;
			ip->ip_id = ip->ip_sum;
			ip->ip_sum = tmp;
		}
	}

	if (opt_v) {
		struct protoent *pe;
		uint16_t sport, dport;
		const char *qs = "";
		const char *qe = "";
		size_t addrsize = sizeof(struct in_addr);

		printf("\n");

		l2pkt_extract(l2pkt);

		pe = getprotobynumber(l2pkt->info.proto);
		if (pe != NULL)
			printf("Protocol %s(%d), ", pe->p_name, l2pkt->info.proto);
		else
			printf("Protocol %d, ", l2pkt->info.proto);
		endprotoent();

		if (l2pkt->info.family == AF_INET6) {
			addrsize = sizeof(struct in6_addr);
			qs = "[";
			qe = "]";
		}

		if (PROTO_HAS_PORT(l2pkt->info.proto)) {
			printf("%s%s%s:%d -> %s%s%s:%d\n",
			    qs, straddr(l2pkt->info.family, &l2pkt->info.src), qe, ntohs(l2pkt->info.sport),
			    qs, straddr(l2pkt->info.family, &l2pkt->info.dst), qe, ntohs(l2pkt->info.dport));
		} else {
			printf("%s -> %s\n",
			    straddr(l2pkt->info.family, &l2pkt->info.src),
			    straddr(l2pkt->info.family, &l2pkt->info.dst));
		}

		if (opt_family == AF_INET6)
			printf("L3 cksum: -\n");
		else
			printf("L3 cksum: 0x%04x (~0x%04x)\n", ntohs(l2pkt->info.l3csum), ~ntohs(l2pkt->info.l3csum) & 0xffff);
		printf("L4 cksum: 0x%04x (~0x%04x)\n", ntohs(l2pkt->info.l4csum), ~ntohs(l2pkt->info.l4csum) & 0xffff);

		uint32_t hash = toeplitz_hash(rsskey, sizeof(rsskey), 
		    &l2pkt->info.src, addrsize,
		    &l2pkt->info.dst, addrsize,
		    NULL);
		printf("RssHash(2-tuple): 0x%08x\n", hash);

		if (PROTO_HAS_PORT(l2pkt->info.proto)) {
			uint32_t hash_p = toeplitz_hash(rsskey, sizeof(rsskey), 
			    &l2pkt->info.src, addrsize,
			    &l2pkt->info.dst, addrsize,
			    &l2pkt->info.sport, sizeof(l2pkt->info.sport),
			    &l2pkt->info.dport, sizeof(l2pkt->info.dport),
			    NULL);
			printf("RssHash(4-tuple): 0x%08x\n", hash_p);
		}

		printf("\n");
		printf("framesize:  %d bytes\n", framesize);
		printf("packetsize: %d bytes\n", packetsize);
	}

	if (opt_hexdump) {
		printf("L2 framesize = %d, L3 packetsize = %d\n", framesize, packetsize);
		packetdump(L2PKT_L2BUF(l2pkt), framesize, (opt_hexdump == 1));
	}

	for (nsend = 0; nsend < npacket; nsend++) {
		r = write(bpf_fd, L2PKT_L2BUF(l2pkt), L2PKT_L2SIZE(l2pkt));
		if (r < 0)
			err(3, "write");
		if (opt_v) {
			if (npacket == 1)
				printf("writing %llu bytes\n", (unsigned long long)r);
			else
				printf("writing %llu bytes (%lu th)\n", (unsigned long long)r, nsend);
		}

	}

	exit(0);
}

int
bpf_open(const char *ifname)
{
	struct bpf_version bv;
	struct ifreq ifr;
	int fd, n;
	char devbpf[sizeof "/dev/bpf0000000000000"];

	n = 0;
	do {
		(void)snprintf(devbpf, sizeof devbpf, "/dev/bpf%d", n++);
		fd = open(devbpf, O_WRONLY);
	} while (fd < 0 && errno == EBUSY);

	if (fd < 0) {
		warn("open");
		goto failure;
	}

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		warn("ioctl: BIOCVERSION");
		goto failure;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		warnx("kernel bpf filter out of date");
		goto failure;
	}

	(void)strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) < 0) {
		warn("ioctl: BIOCSETIF: %s", ifname);
		goto failure;
	}

	return fd;

 failure:
	if (fd >= 0)
		(void)close(fd);
	return -1;
}
