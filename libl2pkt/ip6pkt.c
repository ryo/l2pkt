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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

int
l2pkt_ip6_proto_template(struct l2pkt *l2pkt, uint8_t proto, uint16_t protolen)
{
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);

	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = htons(protolen);
	ip6->ip6_nxt = proto;

	return 0;
}

int
l2pkt_ip6_icmp6_template(struct l2pkt *l2pkt, uint16_t icmp6len)
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;

	l2pkt_ip6_proto_template(l2pkt, IPPROTO_ICMPV6, icmp6len);

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt));
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, ip6->ip6_nxt, (char *)icmp6, icmp6len);

	return 0;
}

int
l2pkt_ip6_udp_template(struct l2pkt *l2pkt, uint16_t udplen)
{
	struct ip6_hdr *ip6;
	struct udphdr *udp;

	l2pkt_ip6_proto_template(l2pkt, IPPROTO_UDP, udplen);

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	udp = (struct udphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt));
	udp->uh_ulen = htons(udplen);
	udp->uh_sum = 0;
	udp->uh_sum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, ip6->ip6_nxt, (char *)udp, udplen);

	return 0;
}

int
l2pkt_ip6_tcp_template(struct l2pkt *l2pkt, uint16_t tcplen)
{
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;

	l2pkt_ip6_proto_template(l2pkt, IPPROTO_TCP, tcplen);

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	tcp = (struct tcphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt));
	tcp->th_off = sizeof(struct tcphdr) / 4;
	tcp->th_sum = 0;
	tcp->th_sum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, ip6->ip6_nxt, (char *)tcp, tcplen);

	return 0;
}

static int
l2pkt_ip6_srcdst(struct l2pkt *l2pkt, int srcdst, struct in6_addr *addr)
{
	struct ip6_hdr *ip6;
	struct in6_addr *old;
	int i;
	uint32_t sum;
	uint16_t *addr16;
	uint8_t proto;

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	old = srcdst ? &ip6->ip6_dst : &ip6->ip6_src;

	proto = l2pkt_getl4protocol(l2pkt);
	switch (proto) {
	case IPPROTO_UDP:
		{
			struct udphdr *udp = (struct udphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt));
			sum = ~udp->uh_sum & 0xffff;
			for (addr16 = (uint16_t *)old, i = 0; i < 8; i++)
				sum -= *addr16++;
			for (addr16 = (uint16_t *)addr, i = 0; i < 8; i++)
				sum += *addr16++;
			udp->uh_sum = ~reduce1(sum);
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt));
			sum = ~tcp->th_sum & 0xffff;
			for (addr16 = (uint16_t *)old, i = 0; i < 8; i++)
				sum -= *addr16++;
			for (addr16 = (uint16_t *)addr, i = 0; i < 8; i++)
				sum += *addr16++;
			tcp->th_sum = ~reduce1(sum);
		}
		break;
	}

	if (srcdst == 0)
		memcpy(old, addr, sizeof(struct in6_addr));
	else
		memcpy(old, addr, sizeof(struct in6_addr));
	return 0;
}


int
l2pkt_ip6_src(struct l2pkt *l2pkt, struct in6_addr *addr)
{
	return l2pkt_ip6_srcdst(l2pkt, 0, addr);
}

int
l2pkt_ip6_dst(struct l2pkt *l2pkt, struct in6_addr *addr)
{
	return l2pkt_ip6_srcdst(l2pkt, 1, addr);
}

int
l2pkt_ip6_ttl(struct l2pkt *l2pkt, uint8_t ttl)
{
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	ip6->ip6_hlim = ttl;
	return 0;
}

int
l2pkt_ip6_prepend_exthdr(struct l2pkt *l2pkt, const char *exthdr, unsigned int exthdrlen)
{
	struct ip6_hdr *ip6;
	char *nxtp;

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	nxtp = (char *)(ip6 + 1);

	uint16_t oldlen = ntohs(ip6->ip6_plen);
	ip6->ip6_nxt = IPPROTO_FRAGMENT;

	// XXX: L3 header will enlarge. L4 length will be decreased.
//	ip6->ip6_plen = htons(oldlen + exthdrlen);

	memmove(nxtp + exthdrlen, nxtp, oldlen);
	memcpy(nxtp, exthdr, exthdrlen);

	return 0;
}

int
l2pkt_ip6_off(struct l2pkt *l2pkt, uint16_t off, bool morefrag, uint16_t id)
{
	struct ip6_hdr *ip6;
	struct ip6_frag ip6frag;

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);

	memset(&ip6frag, 0, sizeof(ip6frag));
	ip6frag.ip6f_nxt = ip6->ip6_nxt;
	ip6frag.ip6f_offlg = htons(off) | (morefrag ? IP6F_MORE_FRAG : 0);
	ip6frag.ip6f_ident = htons(id);


	return l2pkt_ip6_prepend_exthdr(l2pkt, (char *)&ip6frag, sizeof(ip6frag));
}
