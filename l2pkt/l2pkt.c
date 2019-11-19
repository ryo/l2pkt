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
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define	MAXFRAMESIZE	(1024 * 64)
#define	MAXPACKETSIZE	(MAXFRAMESIZE - sizeof(struct ether_header))


int bpf_open(const char *);

static int opt_v;
static int opt_bad_ip4csum = 0;
static int opt_bad_l4csum = 0;
static struct l2pkt *l2pkt;


struct option long_options[] = {
	{ "src",		required_argument,	NULL, 0 },
	{ "dst",		required_argument,	NULL, 0 },
	{ "proto",		required_argument,	NULL, 0 },
	{ "fragoff",		required_argument,	NULL, 0 },
	{ "srcport",		required_argument,	NULL, 0 },
	{ "dstport",		required_argument,	NULL, 0 },
	{ "ip4csum",		required_argument,	NULL, 0 },
	{ "bad-ip4csum",	no_argument,		&opt_bad_ip4csum, 1 },
	{ "l4csum",		required_argument,	NULL, 0 },
	{ "bad-l4csum",		no_argument,		&opt_bad_l4csum, 1 },
	{ 0, 0, 0, 0 }
};

static void
usage()
{
	fprintf(stderr, "usage: l2pkt [option]\n");
	fprintf(stderr, "	-D <etheraddr>		destination mac address (default: ff:ff:ff:ff:ff:ff)\n");
	fprintf(stderr, "	-S <etheraddr>		source mac address (default: own addr)\n");
	fprintf(stderr, "	-X			dump generated packet\n");
//	fprintf(stderr, "	-a			build arp query packet\n");
	fprintf(stderr, "	-4			build IPv4 packet\n");
//	fprintf(stderr, "	-6			build IPv6 packet\n");
	fprintf(stderr, "	--src <addr>		source address\n");
	fprintf(stderr, "	--dst <addr>		destination address\n");
	fprintf(stderr, "	--proto <proto>		protocol\n");
	fprintf(stderr, "	--fragoff <offset>	fragment offset (default: 0)\n");
	fprintf(stderr, "	--srcport <port>	source port\n");
	fprintf(stderr, "	--dstport <port>	destination port\n");
	fprintf(stderr, "	--ip4csum <sum>		specify IPv4 checksum\n"
			"				(adjusting with modifying ip_id)\n");
	fprintf(stderr, "	--bad-ip4csum		don't adjust IPv4 checksum\n");
	fprintf(stderr, "	--l4csum <sum>		specify L4 checksum (TCP,UDP,ICMP)\n"
			"				(adjusting with modifying last 2 bytes of payload)\n");
	fprintf(stderr, "	--bad-l4csum		don't adjust L4 checksum\n");

//	fprintf(stderr, "	--rsshash <hash>	specify rsshash\n");

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

static int
parseint(const char *str, int *v, int min, int max)
{
	long long int x;
	char *ep = NULL;

	x = strtoll(str, &ep, 10);
	if (ep == str)
		return -1;
	if (x < min)
		return -2;
	if (x > max)
		return -3;

	*v = x;
	return 0;
}

static int
parsehex(const char *str, int *v, unsigned int min, unsigned int max)
{
	long long int x;
	char *ep = NULL;

	x = strtoll(str, &ep, 16);
	if (ep == str)
		return -1;
	if (x < min)
		return -2;
	if (x > max)
		return -3;

	*v = x;
	return 0;
}

static int
parsenum(const char *str, int *v, unsigned int min, unsigned int max)
{
	long long int x;
	char *ep = NULL;

	x = strtoll(str, &ep, 0);
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
	ssize_t r;
	int npacket = 1;
	unsigned long nsend;
	int bpf_fd, ch;
	int bpf_hdrcmplt = 0;
	int opt_timestamp = 0;
	int opt_randseed = getpid();
	int opt_random = 0;
	int opt_protocol = IPPROTO_IP;
	bool opt_ip4src = false;
	bool opt_ip4dst = false;
	bool opt_srcport = false;
	bool opt_dstport = false;
	bool opt_X = false;
	int opt_fragoff = 0;
	int opt_ip4csum = -1;
	int opt_l4csum = -1;
	struct in_addr ip4src, ip4dst;
	int srcport, dstport;
	int i;
	int family = 0;
	int packetsize = -1;
	int framesize = -1;
	int ethertype = 0x88b5;	/* IEEE Std 802 - Local Experimental Ethertype */
	char *ifname = NULL;

	memset(&eaddr_src, 0x00, sizeof(eaddr_src));
	memset(&eaddr_dst, 0xff, sizeof(eaddr_dst));

	while ((ch = getopt_long(argc, argv, "46D:R:S:TXf:i:t:n:rs:v", long_options, NULL)) != -1) {
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
				} else if (strcmp("--src", optname) == 0) {
					opt_ip4src = true;
					if (inet_aton(optarg, &ip4src) == 0)
						errx(1, "invalid address: %s", optarg);
				} else if (strcmp("--dst", optname) == 0) {
					opt_ip4dst = true;
					if (inet_aton(optarg, &ip4dst) == 0)
						errx(1, "invalid address: %s", optarg);
				} else if (strcmp("--srcport", optname) == 0) {
					opt_srcport = true;
					if (parseint(optarg, &srcport, 0, 65535) != 0)
						errx(1, "invalid srcport: %s", optarg);
				} else if (strcmp("--dstport", optname) == 0) {
					opt_dstport = true;
					if (parseint(optarg, &dstport, 0, 65535) != 0)
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
				} else {
					errx(1, "unknown option: %s", optname);
				}
			}
			break;

		case '4':
			family = 4;
			ethertype = ETHERTYPE_IP;
			break;
		case '6':
			family = 6;
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
			opt_X = true;
			break;
		case 'f':
			if (parseint(optarg, &framesize, 0, MAXFRAMESIZE) != 0)
				errx(1, "illegal framesize: %s", optarg);
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'n':
			if (parseint(optarg, &npacket, 0, INT_MAX) != 0)
				errx(1, "illegal number: %s", optarg);
			break;
		case 'R':
			if (parsenum(optarg, &opt_randseed, 0, 0x7fffffff) != 0)
				errx(1, "illegal number: %s", optarg);
			break;
		case 'r':
			opt_random = 1;
			break;
		case 's':
			if (parseint(optarg, &packetsize, 0, MAXPACKETSIZE) != 0)
				errx(1, "illegal packetsize: %s", optarg);
			break;
		case 't':
			if (parsehex(optarg, &ethertype, 0, 0xffff) != 0)
				errx(1, "illegal ethertype: %s", optarg);
			break;
		case 'v':
			opt_v++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ((argc != 0) || (ifname == NULL))
		usage();


	if ((framesize == -1) && (packetsize == -1)) {
		packetsize = 46;
		framesize = packetsize + sizeof(struct ether_header);
	} else if (framesize == -1) {
		framesize = packetsize + sizeof(struct ether_header);
	} else if (packetsize == -1) {
		packetsize = framesize - sizeof(struct ether_header);
	} else if (framesize < packetsize + sizeof(struct ether_header)) {
		fprintf(stderr, "Warning: framesize (%d) is greater than packetsize (%d) + 14\n", framesize, packetsize);
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
	if (family) {
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
			l2pkt_ip4_proto_template(l2pkt, opt_protocol, packetsize - sizeof(struct ip));
			break;
		}

//XXX:DEBUG
//		l2pkt_ip4_off(l2pkt, 1234);
//		l2pkt_ip4_id(l2pkt, 0x8765);
//		l2pkt_ip4_ttl(l2pkt, 123);

//XXX:DEBUG
//		if (opt_protocol == IPPROTO_TCP) {
//			l2pkt_tcpseq(l2pkt, 0x12345678);
//			l2pkt_tcpack(l2pkt, 0xabcdef01);
//		}

		if (opt_ip4src)
			l2pkt_ip4_src(l2pkt, ip4src.s_addr);
		if (opt_ip4dst)
			l2pkt_ip4_dst(l2pkt, ip4dst.s_addr);
		if (opt_srcport)
			l2pkt_ip4_srcport(l2pkt, srcport);
		if (opt_dstport)
			l2pkt_ip4_dstport(l2pkt, dstport);

		if (opt_l4csum >= 0) {
			int l4hdrlen = l2pkt_getl4hdrlength(l2pkt);
			int l4len = l2pkt_getl4length(l2pkt);
			if ((l4len - l4hdrlen) < sizeof(uint16_t))
				errx(5, "no space in L4 payload for adjusting checksum. increase packetsize");

			if (opt_bad_l4csum) {
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

		if (opt_fragoff != 0) {
			l2pkt_ip4_off(l2pkt, opt_fragoff);
		}

		if (opt_ip4csum >= 0) {
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
	}

	if (opt_v) {
		printf("framesize:  %d bytes\n", framesize);
		printf("packetsize: %d bytes\n", packetsize);
	}

	for (nsend = 0; nsend < npacket; nsend++) {
		if (opt_X) {
			printf("L2 framesize = %d, L3 packetsize = %d\n", framesize, packetsize);
			packetdump(L2PKT_L2BUF(l2pkt), framesize + 32);
		}

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
