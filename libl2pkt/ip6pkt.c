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

static int
chain_exthdr_proto(uint8_t proto, char *exthdr, unsigned int exthdrlen, uint8_t nxt)
{
	int protochain;
	uint8_t *protop;
	char *end_of_exthdr, *p;

	protop = NULL;
	protochain = 1;
	p = exthdr;
	end_of_exthdr = exthdr + exthdrlen;
	do {
		switch (proto) {
		case IPPROTO_FRAGMENT:
			{
				struct ip6_frag *ip6fragp = (struct ip6_frag *)p;
				p += sizeof(struct ip6_frag);
				protop = &ip6fragp->ip6f_nxt;
				proto = ip6fragp->ip6f_nxt;
				protochain = 0;
			}
			break;
		case IPPROTO_ROUTING:
			{
				struct ip6_rthdr *ip6rthdrp = (struct ip6_rthdr *)p;
				p += (ip6rthdrp->ip6r_len + 1) * 8;
				protop = &ip6rthdrp->ip6r_nxt;
				proto = ip6rthdrp->ip6r_nxt;
			}
			break;
		case IPPROTO_DSTOPTS:
		case IPPROTO_HOPOPTS:
			{
				struct ip6_ext *ip6extp = (struct ip6_ext *)p;
				p += (ip6extp->ip6e_len + 1) * 8;
				protop = &ip6extp->ip6e_nxt;
				proto = ip6extp->ip6e_nxt;
			}
			break;
		case IPPROTO_AH:
			{
				struct ip6_ext *ip6extp = (struct ip6_ext *)p;
				p += (ip6extp->ip6e_len + 2) * 4;
				protop = &ip6extp->ip6e_nxt;
				proto = ip6extp->ip6e_nxt;
			}
			break;
		default:
			protochain = 0;
			break;
		}
	} while (protochain != 0 && (end_of_exthdr < p));

	if (protop != NULL)
		*protop = nxt;

	return 0;
}

int
l2pkt_ip6_proto_template(struct l2pkt *l2pkt, uint8_t exthdrproto, const char *exthdr, unsigned int exthdrlen, uint8_t proto, uint16_t protolen)
{
	struct ip6_hdr *ip6;

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);

	ip6->ip6_vfc = IPV6_VERSION;
	if (exthdr != NULL) {
		struct ip6_ext *ip6extp = (struct ip6_ext *)(ip6 + 1);

		memcpy(ip6extp, exthdr, exthdrlen);
		chain_exthdr_proto(exthdrproto, (char *)ip6extp, exthdrlen, proto);
		ip6->ip6_plen = htons(exthdrlen + protolen);
		ip6->ip6_nxt = exthdrproto;
	} else {
		ip6->ip6_plen = htons(protolen);
		ip6->ip6_nxt = proto;
	}

	return 0;
}

int
l2pkt_ip6_icmp6_template(struct l2pkt *l2pkt, uint8_t exthdrproto, const char *exthdr, unsigned int exthdrlen, uint16_t icmp6len)
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;

	l2pkt_ip6_proto_template(l2pkt, exthdrproto, exthdr, exthdrlen, IPPROTO_ICMPV6, icmp6len);

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	icmp6 = (struct icmp6_hdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt, NULL));
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, IPPROTO_ICMPV6, (char *)icmp6, icmp6len);

	return 0;
}

int
l2pkt_ip6_udp_template(struct l2pkt *l2pkt, uint8_t exthdrproto, const char *exthdr, unsigned int exthdrlen, uint16_t udplen)
{
	struct ip6_hdr *ip6;
	struct udphdr *udp;

	l2pkt_ip6_proto_template(l2pkt, exthdrproto, exthdr, exthdrlen, IPPROTO_UDP, udplen);

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	udp = (struct udphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt, NULL));

	udp->uh_ulen = htons(udplen);
	udp->uh_sum = 0;
	udp->uh_sum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, IPPROTO_UDP, (char *)udp, udplen);

	return 0;
}

int
l2pkt_ip6_tcp_template(struct l2pkt *l2pkt, uint8_t exthdrproto, const char *exthdr, unsigned int exthdrlen,  uint16_t tcplen)
{
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;

	l2pkt_ip6_proto_template(l2pkt, exthdrproto, exthdr, exthdrlen, IPPROTO_TCP, tcplen);

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	tcp = (struct tcphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt, NULL));
	tcp->th_off = sizeof(struct tcphdr) / 4;
	tcp->th_sum = 0;
	tcp->th_sum = in6_cksum(&ip6->ip6_src, &ip6->ip6_dst, IPPROTO_TCP, (char *)tcp, tcplen);

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
			struct udphdr *udp = (struct udphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt, NULL));
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
			struct tcphdr *tcp = (struct tcphdr *)((char *)ip6 + l2pkt_getl3hdrlength(l2pkt, NULL));
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
	char *nxtp, nxt0;

	ip6 = (struct ip6_hdr *)L2PKT_L3BUF(l2pkt);
	nxtp = (char *)(ip6 + 1);

	uint16_t oldlen = ntohs(ip6->ip6_plen);
	nxt0 = ip6->ip6_nxt;
	ip6->ip6_nxt = exthdr[0];

	// XXX: L3 header will be enlarged. L4 length will be decreased.
//	ip6->ip6_plen = htons(oldlen + exthdrlen);
//	l2pkt_setframesize(l2pkt, L2PKT_L2SIZE(l2pkt) + exthdrlen);


	memmove(nxtp + exthdrlen, nxtp, oldlen);
	memcpy(nxtp, exthdr, exthdrlen);
	nxtp[0] = nxt0;

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
