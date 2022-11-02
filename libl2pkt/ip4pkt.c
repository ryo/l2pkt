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
#include "libl2pkt.h"

#include <string.h>
#ifdef __FreeBSD__
#include <sys/stddef.h>
#else
#include <stddef.h>
#endif
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>

int
l2pkt_ip4_arpparse(struct l2pkt *l2pkt, int *op, struct ether_addr *sha, in_addr_t *spa)
{
	struct arppkt *arp;

	arp = (struct arppkt *)L2PKT_BUFFER(l2pkt);

	/* extract arp query packet */
	*op = ntohs(arp->arp.ar_op);
	memcpy(sha, arp->arp.ar_sha, ETHER_ADDR_LEN);
	*spa = arp->arp.ar_spa.s_addr;

	return 0;
}

int
l2pkt_ip4_arpquery(struct l2pkt *l2pkt, const struct ether_addr *sha, in_addr_t spa, in_addr_t tpa)
{
	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	struct arppkt *aquery;

	aquery = (struct arppkt *)L2PKT_BUFFER(l2pkt);

	/* build arp query packet */
	memset(aquery, 0, sizeof(struct arppkt));
	memcpy(aquery->eheader.ether_dhost, eth_broadcast, ETHER_ADDR_LEN);
	memcpy(aquery->eheader.ether_shost, sha, ETHER_ADDR_LEN);
	aquery->eheader.ether_type = htons(ETHERTYPE_ARP);
	aquery->arp.ar_hrd = htons(ARPHRD_ETHER);
	aquery->arp.ar_pro = htons(ETHERTYPE_IP);
	aquery->arp.ar_hln = ETHER_ADDR_LEN;
	aquery->arp.ar_pln = sizeof(struct in_addr);
	aquery->arp.ar_op = htons(ARPOP_REQUEST);
	memcpy(aquery->arp.ar_sha, sha, ETHER_ADDR_LEN);
	aquery->arp.ar_spa.s_addr = spa;
	aquery->arp.ar_tpa.s_addr = tpa;

	return sizeof(struct arppkt);
}

int
l2pkt_ip4_arpreply(struct l2pkt *l2pkt, const char *querybuf, u_char *eaddr, in_addr_t addr, in_addr_t mask)
{
	struct arppkt *aquery, *areply;

	aquery = (struct arppkt *)querybuf;
	areply = (struct arppkt *)L2PKT_BUFFER(l2pkt);

	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	/* checking destination ether addr is broadcast */
	if ((ntohs(aquery->eheader.ether_type) != ETHERTYPE_ARP) ||
	    (memcmp(aquery->eheader.ether_dhost, eth_broadcast, ETHER_ADDR_LEN) != 0) ||
	    (ntohs(aquery->arp.ar_hrd) != ARPHRD_ETHER) ||
	    (ntohs(aquery->arp.ar_pro) != ETHERTYPE_IP) ||
	    (aquery->arp.ar_hln != ETHER_ADDR_LEN) ||
	    (aquery->arp.ar_pln != sizeof(struct in_addr)) ||
	    (ntohs(aquery->arp.ar_op) != ARPOP_REQUEST) ||
	    ((aquery->arp.ar_tpa.s_addr & mask) != (addr & mask)))
		return -1;	/* not an arp request packet for me */

	/* build arp reply packet */
	memset(areply, 0, sizeof(struct arppkt));
	memcpy(areply->eheader.ether_dhost, aquery->arp.ar_sha, ETHER_ADDR_LEN);
	memcpy(areply->eheader.ether_shost, eaddr, ETHER_ADDR_LEN);
	areply->eheader.ether_type = htons(ETHERTYPE_ARP);
	areply->arp.ar_hrd = htons(ARPHRD_ETHER);
	areply->arp.ar_pro = htons(ETHERTYPE_IP);
	areply->arp.ar_hln = ETHER_ADDR_LEN;
	areply->arp.ar_pln = sizeof(struct in_addr);
	areply->arp.ar_op = htons(ARPOP_REPLY);
	memcpy(areply->arp.ar_sha, eaddr, ETHER_ADDR_LEN);
	memcpy(&areply->arp.ar_spa, &aquery->arp.ar_tpa, sizeof(struct in_addr));
	memcpy(areply->arp.ar_tha, aquery->arp.ar_sha, ETHER_ADDR_LEN);
	memcpy(&areply->arp.ar_tpa, &aquery->arp.ar_spa, sizeof(struct in_addr));

	return sizeof(struct arppkt);
}

int
l2pkt_ip4_proto_template(struct l2pkt *l2pkt, uint8_t proto, uint16_t protolen)
{
	struct ip *ip;
	unsigned int iplen;

	iplen = sizeof(struct ip) + protolen;
	ip = (struct ip *)L2PKT_L3BUF(l2pkt);

	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) / 4;

	ip->ip_len = htons(iplen);
	ip->ip_off = 0;
	ip->ip_p = proto;
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum(0, (char *)ip, sizeof(struct ip));

	return 0;
}

int
l2pkt_ip4_icmp_template(struct l2pkt *l2pkt, uint16_t icmplen)
{
	struct ip *ip;
	struct icmp *icmp;

	l2pkt_ip4_proto_template(l2pkt, IPPROTO_ICMP, icmplen);

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	icmp = (struct icmp *)((char *)ip + l2pkt_getl3hdrlength(l2pkt, NULL));
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum(0, (char *)icmp, icmplen);

	return 0;
}

int
l2pkt_ip4_udp_template(struct l2pkt *l2pkt, uint16_t udplen)
{
	struct ip *ip;
	struct udphdr *udp;

	l2pkt_ip4_proto_template(l2pkt, IPPROTO_UDP, udplen);

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	udp = (struct udphdr *)((char *)ip + l2pkt_getl3hdrlength(l2pkt, NULL));
	udp->uh_ulen = htons(udplen);
	udp->uh_sum = 0;
	udp->uh_sum = in4_cksum(ip->ip_src, ip->ip_dst, ip->ip_p, (char *)udp, udplen);
	if (udp->uh_sum == 0)
		udp->uh_sum = 0xffff;

	return 0;
}

int
l2pkt_ip4_tcp_template(struct l2pkt *l2pkt, uint16_t tcplen)
{
	struct ip *ip;
	struct tcphdr *tcp;

	l2pkt_ip4_proto_template(l2pkt, IPPROTO_TCP, tcplen);

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	tcp = (struct tcphdr *)((char *)ip + l2pkt_getl3hdrlength(l2pkt, NULL));
	tcp->th_off = sizeof(struct tcphdr) / 4;
	tcp->th_sum = 0;
	tcp->th_sum = in4_cksum(ip->ip_src, ip->ip_dst, ip->ip_p, (char *)tcp, tcplen);

	return 0;
}

int
l2pkt_ip4_length(struct l2pkt *l2pkt, uint16_t iplen)
{
	struct ip *ip;
	uint32_t sum;
	uint16_t oldlen;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v != IPVERSION)
		return -1;

	oldlen = ip->ip_len;
	ip->ip_len = htons(iplen);
	sum = ~ip->ip_sum & 0xffff;
	sum -= oldlen;
	sum += ip->ip_len;
	ip->ip_sum = ~reduce1(sum);

	switch (ip->ip_p) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);

			oldlen = udp->uh_ulen;
			udp->uh_ulen = htons(iplen - ip->ip_hl * 4);
			sum = ~udp->uh_sum & 0xffff;
			sum -= oldlen;	/* for pseudo header */
			sum -= oldlen;	/* for udp->uh_ulen */
			sum += udp->uh_ulen;	/* for pseudo header */
			sum += udp->uh_ulen;	/* for udp->uh_ulen */
			udp->uh_sum = ~reduce1(sum);
			if (udp->uh_sum == 0)
				udp->uh_sum = 0xffff;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);

			oldlen = ntohs(oldlen) - ip->ip_hl * 4;
			sum = ~tcp->th_sum & 0xffff;
			sum -= htons(oldlen);
			sum += htons(iplen - ip->ip_hl * 4);
			tcp->th_sum = ~reduce1(sum);
		}
		break;
	case IPPROTO_ICMP:
		/* icmp checksum does not depend on packet length */
		break;

	default:
		fprintf(stderr, "%s:%d: protocol %d is not supported\n", __func__, __LINE__, ip->ip_p);
		return -1;
	}

	return 0;
}

int
l2pkt_ip4_off(struct l2pkt *l2pkt, uint16_t off)
{
	struct ip *ip;
	uint32_t sum;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v != IPVERSION)
		return -1;

	off = htons(off);
	sum = ~ip->ip_sum & 0xffff;
	sum -= ip->ip_off & 0xffff;
	sum += off & 0xffff;
	ip->ip_sum = ~reduce1(sum);
	ip->ip_off = off;

	return 0;
}

int
l2pkt_ip4_id(struct l2pkt *l2pkt, uint16_t id)
{
	struct ip *ip;
	uint32_t sum;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v != IPVERSION)
		return -1;

	id = htons(id);
	sum = ~ip->ip_sum & 0xffff;
	sum -= ip->ip_id & 0xffff;
	sum += id & 0xffff;
	ip->ip_sum = ~reduce1(sum);
	ip->ip_id = id;

	return 0;
}

int
l2pkt_ip4_tos(struct l2pkt *l2pkt, uint8_t tos)
{
	struct ip *ip;
	uint32_t sum;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v != IPVERSION)
		return -1;

	sum = ~ip->ip_sum & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum -= (ip->ip_tos << 8);
	sum += tos << 8;
#else
	sum -= (ip->ip_tos);
	sum += tos;
#endif
	ip->ip_sum = ~reduce1(sum);
	ip->ip_tos = tos;

	return 0;
}

int
l2pkt_ip4_ttl(struct l2pkt *l2pkt, uint8_t ttl)
{
	struct ip *ip;
	uint32_t sum;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v != IPVERSION)
		return -1;

	sum = ~ip->ip_sum & 0xffff;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	sum -= (ip->ip_ttl);
	sum += ttl;
#else
	sum -= (ip->ip_ttl << 8);
	sum += ttl << 8;
#endif
	ip->ip_sum = ~reduce1(sum);
	ip->ip_ttl = ttl;

	return 0;
}

static int
l2pkt_ip4_srcdst(struct l2pkt *l2pkt, int srcdst, in_addr_t addr)
{
	struct ip *ip;
	uint32_t sum;
	in_addr_t old;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v != IPVERSION)
		return -1;

	if (srcdst == 0)
		old = ip->ip_src.s_addr;
	else
		old = ip->ip_dst.s_addr;

	sum = ~ip->ip_sum & 0xffff;
	sum -= (old >> 16) & 0xffff;
	sum -= old & 0xffff;
	sum += (addr >> 16) & 0xffff;
	sum += addr & 0xffff;

	ip->ip_sum = ~reduce1(sum);
	if (srcdst == 0)
		ip->ip_src.s_addr = addr;
	else
		ip->ip_dst.s_addr = addr;

	if (ip->ip_p == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)((char *)ip + ip->ip_hl * 4);
		sum = ~udp->uh_sum & 0xffff;
		sum -= (old >> 16) & 0xffff;
		sum -= old & 0xffff;
		sum += (addr >> 16) & 0xffff;
		sum += addr & 0xffff;
		udp->uh_sum = ~reduce1(sum);
		if (udp->uh_sum == 0)
			udp->uh_sum = 0xffff;
	} else if (ip->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *)((char *)ip + ip->ip_hl * 4);
		sum = ~tcp->th_sum & 0xffff;
		sum -= (old >> 16) & 0xffff;
		sum -= old & 0xffff;
		sum += (addr >> 16) & 0xffff;
		sum += addr & 0xffff;
		tcp->th_sum = ~reduce1(sum);
	}
	return 0;
}

int
l2pkt_ip4_src(struct l2pkt *l2pkt, in_addr_t addr)
{
	return l2pkt_ip4_srcdst(l2pkt, 0, addr);
}

int
l2pkt_ip4_dst(struct l2pkt *l2pkt, in_addr_t addr)
{
	return l2pkt_ip4_srcdst(l2pkt, 1, addr);
}
