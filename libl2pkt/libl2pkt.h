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

#define LIBL2PKT_MAXPKTSIZE	(1024 * 64)

struct l2pkt {
	unsigned int framesize;
	char buf[LIBL2PKT_MAXPKTSIZE + 1024];
};

#define L2PKT_BUFFER(pkt)	((pkt)->buf)
#define L2PKT_L2BUF(pkt)	L2PKT_BUFFER((pkt))
#define L2PKT_L3BUF(pkt)	(L2PKT_L2BUF((pkt)) + sizeof(struct ether_header))
#define L2PKT_L4BUF(pkt)	(L2PKT_L3BUF((pkt)) + sizeof(struct ip))

#define L2PKT_L2SIZE(pkt)	((pkt)->framesize)
#define L2PKT_L3SIZE(pkt)	(L2PKT_L2SIZE((pkt)) - sizeof(struct ether_header))
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
int l2pkt_ip4_ttl(struct l2pkt *, uint8_t);
int l2pkt_ip4_src(struct l2pkt *, in_addr_t);
int l2pkt_ip4_dst(struct l2pkt *, in_addr_t);

int l2pkt_ip4_proto_template(struct l2pkt *, uint8_t, uint16_t);

int l2pkt_ip4_icmp_template(struct l2pkt *, uint16_t);
//int l2pkt_ip4_icmptype(struct l2pkt *, uint8_t);
//int l2pkt_ip4_icmpcode(struct l2pkt *, uint8_t);
//int l2pkt_ip4_icmpid(struct l2pkt *, uint16_t);
//int l2pkt_ip4_icmpseq(struct l2pkt *, uint16_t);

int l2pkt_ip4_udp_template(struct l2pkt *, uint16_t);
int l2pkt_ip4_tcp_template(struct l2pkt *, uint16_t);
//int l2pkt_ip4_tcpseq(struct l2pkt *, uint32_t);
//int l2pkt_ip4_tcpack(struct l2pkt *, uint32_t);
//int l2pkt_ip4_tcpflags(struct l2pkt *, int);
//int l2pkt_ip4_tcpwin(struct l2pkt *, uint16_t);
//int l2pkt_ip4_tcpurp(struct l2pkt *, uint16_t);

int l2pkt_ip4_srcport(struct l2pkt *, uint16_t);
int l2pkt_ip4_dstport(struct l2pkt *, uint16_t);
int l2pkt_ip4_l4writedata(struct l2pkt *, unsigned int, char *, unsigned int);


//int l2pkt_ip4_writedata(struct l2pkt *, unsigned int, char *, unsigned int);
//int l2pkt_ip4_readdata(struct l2pkt *, unsigned int, char *, unsigned int);
//char *l2pkt_ip4_getptr(struct l2pkt *, unsigned int);
//
//int l2pkt_ip4_test_cksum(struct l2pkt *, unsigned int);


///* ip6pkt.c */
//int l2pkt_ip6pkt_neighbor_parse(struct l2pkt *, int *, struct ether_addr *, struct in6_addr *);
//int l2pkt_ip6pkt_neighbor_solicit(struct l2pkt *, const struct ether_addr *, struct in6_addr *, struct in6_addr *);
//int l2pkt_ip6pkt_neighbor_solicit_reply(struct l2pkt *, const char *, u_char *, struct in6_addr *);
//int l2pkt_ip6pkt_icmp6_template(struct l2pkt *, unsigned int);
//int l2pkt_ip6pkt_icmp6_echoreply(struct l2pkt *, const char *, unsigned int);
//int l2pkt_ip6pkt_icmp6_type(struct l2pkt *, unsigned int);
//int l2pkt_ip6pkt_udp_template(struct l2pkt *, unsigned int);
//int l2pkt_ip6pkt_tcp_template(struct l2pkt *, unsigned int);
//int l2pkt_ip6pkt_length(struct l2pkt *, unsigned int);
//int l2pkt_ip6pkt_off(struct l2pkt *, uint16_t);
//int l2pkt_ip6pkt_flowinfo(struct l2pkt *, uint32_t);
//int l2pkt_ip6pkt_ttl(struct l2pkt *, int);
//int l2pkt_ip6pkt_src(struct l2pkt *, const struct in6_addr *);
//int l2pkt_ip6pkt_dst(struct l2pkt *, const struct in6_addr *);
//int l2pkt_ip6pkt_srcport(struct l2pkt *, uint16_t);
//int l2pkt_ip6pkt_dstport(struct l2pkt *, uint16_t);
//int l2pkt_ip6pkt_payload(struct l2pkt *, char *, unsigned int);
//
//int l2pkt_ip6pkt_icmptype(struct l2pkt *, uint8_t);
//int l2pkt_ip6pkt_icmpcode(struct l2pkt *, uint8_t);
//int l2pkt_ip6pkt_icmpid(struct l2pkt *, uint16_t);
//int l2pkt_ip6pkt_icmpseq(struct l2pkt *, uint16_t);
//
//int l2pkt_ip6pkt_tcpseq(struct l2pkt *, uint32_t);
//int l2pkt_ip6pkt_tcpack(struct l2pkt *, uint32_t);
//int l2pkt_ip6pkt_tcpflags(struct l2pkt *, int);
//int l2pkt_ip6pkt_tcpwin(struct l2pkt *, uint16_t);
//int l2pkt_ip6pkt_tcpurp(struct l2pkt *, uint16_t);
//
//int l2pkt_ip6pkt_writedata(struct l2pkt *, unsigned int, char *, unsigned int);
//int l2pkt_ip6pkt_readdata(struct l2pkt *, unsigned int, char *, unsigned int);
//char *l2pkt_ip6pkt_getptr(struct l2pkt *, unsigned int);
//
//int l2pkt_ip6pkt_test_cksum(struct l2pkt *, unsigned int);


/* utils */
int fdumpstr(FILE *, const char *, size_t);
int dumpstr(const char *, size_t);
void packetdump(const char *, size_t);

/* tcpdump file output utility */
int tcpdumpfile_open(const char *);
ssize_t tcpdumpfile_output(int, char *, int);
void tcpdumpfile_close(int);

#endif /* _LIBL2PKT_H_ */
