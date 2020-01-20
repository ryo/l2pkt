/*
 * Copyright (c) 2019 Ryo Shimizu <ryo@nerv.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _LIBL2PKT_H_
#define _LIBL2PKT_H_

#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#ifdef __NetBSD__
#include <net/if_ether.h>
#elif defined(__OpenBSD__)
#include <netinet/if_ether.h>
#elif defined(__FreeBSD__)
#include <net/ethernet.h>
#define ether_addr_octet octet
#endif
#include <stdio.h>

/* XXX: for userland. from netinet6/in6.h */
#if BYTE_ORDER == BIG_ENDIAN
#define IPV6_ADDR_INT32_ONE		1
#define IPV6_ADDR_INT32_TWO		2
#define IPV6_ADDR_INT32_MNL		0xff010000
#define IPV6_ADDR_INT32_MLL		0xff020000
#define IPV6_ADDR_INT32_SMP		0x0000ffff
#define IPV6_ADDR_INT16_ULL		0xfe80
#define IPV6_ADDR_INT16_USL		0xfec0
#define IPV6_ADDR_INT16_MLL		0xff02
#elif BYTE_ORDER == LITTLE_ENDIAN
#define IPV6_ADDR_INT32_ONE		0x01000000
#define IPV6_ADDR_INT32_TWO		0x02000000
#define IPV6_ADDR_INT32_MNL		0x000001ff
#define IPV6_ADDR_INT32_MLL		0x000002ff
#define IPV6_ADDR_INT32_SMP		0xffff0000
#define IPV6_ADDR_INT16_ULL		0x80fe
#define IPV6_ADDR_INT16_USL		0xc0fe
#define IPV6_ADDR_INT16_MLL		0x02ff
#endif
#ifndef s6_addr8
#define s6_addr8  __u6_addr.__u6_addr8
#endif
#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif


#define LIBL2PKT_MAXPKTSIZE	(1024 * 64)

struct l2pkt {
	struct {
		int family;	/* AF_INET/AF_INET6 */
		union {
			struct in_addr ip4;
			struct in6_addr ip6;
		} src, dst;
		uint16_t l3csum;	/* IPv4 */
		uint16_t l4csum;	/* TCP/UDP/ICMP */
		uint16_t sport, dport;
		uint8_t proto;
	} info;

	unsigned int framesize;
	char buf[LIBL2PKT_MAXPKTSIZE + 1024];
};

struct ether_vlan_header {
	uint8_t evl_dhost[ETHER_ADDR_LEN];
	uint8_t evl_shost[ETHER_ADDR_LEN];
	uint16_t evl_encap_proto;
	uint16_t evl_tag;
	uint16_t evl_proto;
} __packed;


#define L2PKT_BUFFER(pkt)	((pkt)->buf)
#define L2PKT_L2BUF(pkt)	L2PKT_BUFFER((pkt))
#define L2PKT_L2HEADERSIZE(pkt)	\
	((((struct ether_header *)L2PKT_L2BUF(pkt))->ether_type == htons(ETHERTYPE_VLAN)) ?	\
	    sizeof(struct ether_vlan_header) : sizeof(struct ether_header))
#define L2PKT_L3BUF(pkt)	(L2PKT_L2BUF((pkt)) + L2PKT_L2HEADERSIZE(pkt))
#define L2PKT_L2SIZE(pkt)	((pkt)->framesize)
#define L2PKT_L3SIZE(pkt)	(L2PKT_L2SIZE((pkt)) - L2PKT_L2HEADERSIZE(pkt))
#define L2PKT_IN_RANGE(pkt, p)	(((p) - L2PKT_BUFFER((pkt))) < (pkt)->framesize)

/* ethernet arp packet */
struct arppkt {
	struct ether_header eheader;
	struct {
		uint16_t ar_hrd;			/* +0x00 */
		uint16_t ar_pro;			/* +0x02 */
		uint8_t ar_hln;				/* +0x04 */
		uint8_t ar_pln;				/* +0x05 */
		uint16_t ar_op;				/* +0x06 */
		uint8_t ar_sha[ETHER_ADDR_LEN];		/* +0x08 */
		struct in_addr ar_spa;			/* +0x0e */
		uint8_t ar_tha[ETHER_ADDR_LEN];		/* +0x12 */
		struct in_addr ar_tpa;			/* +0x18 */
							/* +0x1c */
	} __packed arp;
} __packed;

struct ndpkt {
	struct ether_header eheader;
	struct ip6_hdr ip6;
	union {
		struct icmp6_hdr nd_icmp6;
		struct nd_neighbor_solicit nd_solicit;
		struct nd_neighbor_advert nd_advert;
	} nd;
#define nd_solicit	nd.nd_solicit
#define nd_advert	nd.nd_advert
#define nd_icmp6	nd.nd_icmp6
	uint8_t opt[8];
} __packed;

static inline unsigned int align(unsigned int n, unsigned int a)
{
	return (n + a - 1) & (-a);
}

static inline unsigned int
reduce1(uint32_t sum)
{
	if (sum == 0)
		return 0xffff;

	sum = ((sum >> 16) & 0xffff) + (sum & 0xffff);
	sum &= 0xffff;
	if (sum == 0)
		sum++;
	return sum;
}

int l2pkt_init(struct l2pkt *, int);
struct l2pkt *l2pkt_create(int);
void l2pkt_destroy(struct l2pkt *);
int l2pkt_setframesize(struct l2pkt *, unsigned int);

/* cksum.c */
unsigned int in4_cksum(struct in_addr, struct in_addr, int, char *, unsigned int);
unsigned int in6_cksum(struct in6_addr *, struct in6_addr *, int, char *, unsigned int);
unsigned int in_cksum(unsigned int, char *, unsigned int);

/* etherpkt.c */
int l2pkt_ethpkt_template(struct l2pkt *);
int l2pkt_ethpkt_vlan(struct l2pkt *, uint16_t);
int l2pkt_ethpkt_type(struct l2pkt *, uint16_t);
int l2pkt_ethpkt_src(struct l2pkt *, struct ether_addr *);
int l2pkt_ethpkt_dst(struct l2pkt *, struct ether_addr *);

/* ip4pkt.c */
int l2pkt_ip4_arpparse(struct l2pkt *, int *, struct ether_addr *, in_addr_t *);
int l2pkt_ip4_arpquery(struct l2pkt *, const struct ether_addr *, in_addr_t, in_addr_t);
int l2pkt_ip4_arpreply(struct l2pkt *, const char *, u_char *, in_addr_t, in_addr_t);
int l2pkt_ip4_length(struct l2pkt *, uint16_t);
int l2pkt_ip4_off(struct l2pkt *, uint16_t);
int l2pkt_ip4_id(struct l2pkt *, uint16_t);
int l2pkt_ip4_tos(struct l2pkt *, uint8_t);
int l2pkt_ip4_ttl(struct l2pkt *, uint8_t);
int l2pkt_ip4_src(struct l2pkt *, in_addr_t);
int l2pkt_ip4_dst(struct l2pkt *, in_addr_t);
int l2pkt_ip4_proto_template(struct l2pkt *, uint8_t, uint16_t);
int l2pkt_ip4_icmp_template(struct l2pkt *, uint16_t);
int l2pkt_ip4_udp_template(struct l2pkt *, uint16_t);
int l2pkt_ip4_tcp_template(struct l2pkt *, uint16_t);

/* ip6pkt.c */
int l2pkt_ip6_src(struct l2pkt *, struct in6_addr *);
int l2pkt_ip6_dst(struct l2pkt *, struct in6_addr *);
int l2pkt_ip6_proto_template(struct l2pkt *, uint8_t, uint16_t);
int l2pkt_ip6_icmp6_template(struct l2pkt *, uint16_t);
int l2pkt_ip6_udp_template(struct l2pkt *, uint16_t);
int l2pkt_ip6_tcp_template(struct l2pkt *, uint16_t);
int l2pkt_ip6_prepend_exthdr(struct l2pkt *, const char *, unsigned int);
int l2pkt_ip6_off(struct l2pkt *, uint16_t, bool, uint16_t);

/* l4pkt.c */
int l2pkt_extract(struct l2pkt *);	/* extract to l2pkt->info */
int l2pkt_getl3length(struct l2pkt *);
int l2pkt_getl3hdrlength(struct l2pkt *);
int l2pkt_getl4length(struct l2pkt *);
int l2pkt_getl4protocol(struct l2pkt *);
int l2pkt_getl4hdrlength(struct l2pkt *);
int l2pkt_getl4csumoffset(struct l2pkt *);
int l2pkt_l4write(struct l2pkt *, unsigned int, char *, unsigned int);
int l2pkt_l4write_raw(struct l2pkt *, unsigned int, char *, unsigned int);
int l2pkt_l4write_1(struct l2pkt *, unsigned int, uint8_t);
int l2pkt_l4write_2(struct l2pkt *, unsigned int, uint16_t);
int l2pkt_l4write_4(struct l2pkt *, unsigned int, uint32_t);
int l2pkt_l4read(struct l2pkt *, unsigned int, char *, unsigned int);
uint8_t l2pkt_l4read_1(struct l2pkt *, unsigned int);
uint16_t l2pkt_l4read_2(struct l2pkt *, unsigned int);
uint32_t l2pkt_l4read_4(struct l2pkt *, unsigned int);

int l2pkt_srcport(struct l2pkt *, uint16_t);
int l2pkt_dstport(struct l2pkt *, uint16_t);

int l2pkt_icmptype(struct l2pkt *, uint8_t);
int l2pkt_icmpcode(struct l2pkt *, uint8_t);
int l2pkt_icmpid(struct l2pkt *, uint16_t);
int l2pkt_icmpseq(struct l2pkt *, uint16_t);

int l2pkt_tcpseq(struct l2pkt *, uint32_t);
int l2pkt_tcpack(struct l2pkt *, uint32_t);
int l2pkt_tcpflags(struct l2pkt *, uint8_t);
int l2pkt_tcpwin(struct l2pkt *, uint16_t);
int l2pkt_tcpurp(struct l2pkt *, uint16_t);

/* utils */
int fdumpstr(FILE *, const char *, size_t, bool);
int dumpstr(const char *, size_t, bool);
void packetdump(const char *, size_t, bool);

/* tcpdump file output utility */
int tcpdumpfile_open(const char *);
ssize_t tcpdumpfile_output(int, char *, int);
void tcpdumpfile_close(int);

#endif /* _LIBL2PKT_H_ */
