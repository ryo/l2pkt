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

int
l2pkt_getl3length(struct l2pkt *l2pkt)
{
	struct ip *ip;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v == IPVERSION) {
		return ntohs(ip->ip_len);
	}

	return 0;
}

int
l2pkt_getl3hdrlength(struct l2pkt *l2pkt)
{
	struct ip *ip;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v == IPVERSION) {
		return (ip->ip_hl * 4);
	}
	if (ip->ip_v == 6) {
		return sizeof(struct ip6_hdr);	/* XXX */
	}

	return 0;
}

int
l2pkt_getl4protocol(struct l2pkt *l2pkt)
{
	struct ip *ip;
	struct ip6_hdr *ip6;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v == IPVERSION)
		return ip->ip_p;

	if (ip->ip_v == 6) {
		ip6 = (struct ip6_hdr *)ip;
		/* XXX: TODO: add support IPv6 extension header */
		return ip6->ip6_nxt;
	}

	return 0;
}

/* return L4 header size */
int
l2pkt_getl4hdrlength(struct l2pkt *l2pkt)
{
	uint8_t proto = l2pkt_getl4protocol(l2pkt);

	switch (proto) {
	case IPPROTO_ICMPV6:	/* XXX */
	case IPPROTO_ICMP:
		return 8;	/* XXX */
	case IPPROTO_UDP:
		return sizeof(struct udphdr);
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = (struct tcphdr *)(L2PKT_L3BUF(l2pkt) + l2pkt_getl3hdrlength(l2pkt));
			return (tcp->th_off * 4);
		}
	default:
		break;
	}
	return 0;
}

/* return L4 size (including own L4 header) */
int
l2pkt_getl4length(struct l2pkt *l2pkt)
{
	struct ip *ip;
	struct ip6_hdr *ip6;
	uint8_t proto = 0;
	uint16_t protolen;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v == IPVERSION) {
		proto = ip->ip_p;
	} else if (ip->ip_v == 6) {
		ip6 = (struct ip6_hdr *)ip;
		/* XXX: TODO: add support IPv6 extension header */
		return ntohs(ip6->ip6_plen);
	}

	/* IPv4 */
	switch (proto) {
	case IPPROTO_UDP:
		l2pkt_l4read(l2pkt, offsetof(struct udphdr, uh_ulen), (char *)&protolen, sizeof(uint16_t));
		return ntohs(protolen);
	default:
		break;
	}

	/* L4 length is L3 length - L3 header */
	return (ntohs(ip->ip_len) - (ip->ip_hl * 4));
}

/* return checksum offset from top of L4 header */
int
l2pkt_getl4csumoffset(struct l2pkt *l2pkt)
{
	uint8_t proto = l2pkt_getl4protocol(l2pkt);

	switch (proto) {
	case IPPROTO_UDP:
		return offsetof(struct udphdr, uh_sum);
	case IPPROTO_TCP:
		return offsetof(struct tcphdr, th_sum);
	case IPPROTO_ICMPV6:	/* XXX */
	case IPPROTO_ICMP:
		return offsetof(struct icmp, icmp_cksum);
	default:
		break;
	}
	return -1;
}

int
l2pkt_extract(struct l2pkt *l2pkt)
{
	struct ip *ip;
	struct ip6_hdr *ip6;

	ip = (struct ip *)L2PKT_L3BUF(l2pkt);
	if (ip->ip_v == IPVERSION) {
		l2pkt->info.family = AF_INET;
		l2pkt->info.proto = ip->ip_p;
		memcpy(&l2pkt->info.src.ip4, &ip->ip_src, sizeof(struct in_addr));
		memcpy(&l2pkt->info.dst.ip4, &ip->ip_dst, sizeof(struct in_addr));

	} else if (ip->ip_v == 6) {
		ip6 = (struct ip6_hdr *)ip;
		l2pkt->info.family = AF_INET6;

		/* XXX: TODO: add support IPv6 extension header */
		l2pkt->info.proto = ip6->ip6_nxt;

		memcpy(&l2pkt->info.src.ip6, &ip6->ip6_src, sizeof(struct in6_addr));
		memcpy(&l2pkt->info.dst.ip6, &ip6->ip6_dst, sizeof(struct in6_addr));
	}


	switch (l2pkt->info.proto) {
	case IPPROTO_UDP:
		l2pkt_l4read(l2pkt, offsetof(struct udphdr, uh_sport), (char *)&l2pkt->info.sport, sizeof(uint16_t));
		l2pkt_l4read(l2pkt, offsetof(struct udphdr, uh_dport), (char *)&l2pkt->info.dport, sizeof(uint16_t));
		break;
	case IPPROTO_TCP:
		l2pkt_l4read(l2pkt, offsetof(struct tcphdr, th_sport), (char *)&l2pkt->info.sport, sizeof(uint16_t));
		l2pkt_l4read(l2pkt, offsetof(struct tcphdr, th_dport), (char *)&l2pkt->info.dport, sizeof(uint16_t));
		break;
	default:
		break;
	}
	return 0;
}

/* write data with adjusting checksum */
int
l2pkt_l4write(struct l2pkt *l2pkt, unsigned int offset, char *data, unsigned int datalen)
{
	uint16_t *sump;
	char *datap;
	uint32_t sum;

	sump = (uint16_t *)(L2PKT_L3BUF(l2pkt) + l2pkt_getl3hdrlength(l2pkt) + l2pkt_getl4csumoffset(l2pkt));
	datap = L2PKT_L3BUF(l2pkt) + l2pkt_getl3hdrlength(l2pkt) + offset;

	sum = ~*sump & 0xffff;
	{
		if (offset & 1) {
#if _BYTE_ORDER == _LITTLE_ENDIAN
			sum -= (*datap & 0xff) << 8;
			sum += (*data & 0xff) << 8;
#else
			sum -= (*datap & 0xff);
			sum += (*data & 0xff);
#endif
			sum = reduce1(sum);
			*datap++ = *data++;
			datalen--;
		}

		for (; datalen >= 2; datalen -= 2) {
			sum -= *(uint16_t *)datap;
			*(uint16_t *)datap = *(uint16_t *)data;
			sum += *(uint16_t *)data;
			sum = reduce1(sum);

			datap += 2;
			data += 2;
		}

		if (datalen > 0) {
#if _BYTE_ORDER == _LITTLE_ENDIAN
			sum -= (*datap & 0xff);
			sum += (*data & 0xff);
#else
			sum -= (*datap & 0xff) << 8;
			sum += (*data & 0xff) << 8;
#endif
			sum = reduce1(sum);
			*datap++ = *data++;
			datalen--;
		}
	}
	*sump = ~sum;

	return 0;
}

/* write data without adjusting checksum */
int
l2pkt_l4write_raw(struct l2pkt *l2pkt, unsigned int offset, char *data, unsigned int datalen)
{
	char *datap;

	datap = L2PKT_L3BUF(l2pkt) + l2pkt_getl3hdrlength(l2pkt) + offset;

	if (offset & 1) {
		*datap++ = *data++;
		datalen--;
	}

	for (; datalen >= 2; datalen -= 2) {
		*(uint16_t *)datap = *(uint16_t *)data;
		datap += 2;
		data += 2;
	}

	if (datalen > 0) {
		*datap++ = *data++;
		datalen--;
	}

	return 0;
}

int
l2pkt_l4read(struct l2pkt *l2pkt, unsigned int offset, char *data, unsigned int datalen)
{
	char *datap;

	datap = L2PKT_L3BUF(l2pkt) + l2pkt_getl3hdrlength(l2pkt) + offset;

	if (offset & 1) {
		*data++ = *datap++;
		datalen--;
	}

	for (; datalen >= 2; datalen -= 2) {
		*(uint16_t *)data = *(uint16_t *)datap;
		datap += 2;
		data += 2;
	}

	if (datalen > 0) {
		*data++ = *datap++;
		datalen--;
	}

	return 0;
}

int
l2pkt_l4write_1(struct l2pkt *l2pkt, unsigned int offset, uint8_t data)
{
	return l2pkt_l4write(l2pkt, offset, (char *)&data, sizeof(data));
}

int
l2pkt_l4write_2(struct l2pkt *l2pkt, unsigned int offset, uint16_t data0)
{
	uint16_t data = htons(data0);
	return l2pkt_l4write(l2pkt, offset, (char *)&data, sizeof(data));
}

int
l2pkt_l4write_4(struct l2pkt *l2pkt, unsigned int offset, uint32_t data0)
{
	uint32_t data = htonl(data0);
	return l2pkt_l4write(l2pkt, offset, (char *)&data, sizeof(data));
}

uint8_t
l2pkt_l4read_1(struct l2pkt *l2pkt, unsigned int offset)
{
	uint8_t value = 0;

	l2pkt_l4read(l2pkt, offset, (char *)&value, sizeof(value));
	return value;
}

uint16_t
l2pkt_l4read_2(struct l2pkt *l2pkt, unsigned int offset)
{
	uint16_t value = 0;

	l2pkt_l4read(l2pkt, offset, (char *)&value, sizeof(value));
	return ntohs(value);
}

uint32_t
l2pkt_l4read_4(struct l2pkt *l2pkt, unsigned int offset)
{
	uint32_t value = 0;

	l2pkt_l4read(l2pkt, offset, (char *)&value, sizeof(value));
	return ntohl(value);
}

int
l2pkt_icmptype(struct l2pkt *l2pkt, uint8_t type)
{
	return l2pkt_l4write_1(l2pkt, offsetof(struct icmp, icmp_type), type);
}

int
l2pkt_icmpcode(struct l2pkt *l2pkt, uint8_t code)
{
	return l2pkt_l4write_1(l2pkt, offsetof(struct icmp, icmp_code), code);
}

int
l2pkt_icmpid(struct l2pkt *l2pkt, uint16_t id)
{
	return l2pkt_l4write_2(l2pkt, offsetof(struct icmp, icmp_id), id);
}

int
l2pkt_icmpseq(struct l2pkt *l2pkt, uint16_t seq)
{
	return l2pkt_l4write_2(l2pkt, offsetof(struct icmp, icmp_id), seq);
}

int
l2pkt_srcport(struct l2pkt *l2pkt, uint16_t port)
{
	uint8_t proto = l2pkt_getl4protocol(l2pkt);

	switch (proto) {
	case IPPROTO_UDP:
		l2pkt_l4write_2(l2pkt, offsetof(struct udphdr, uh_sport), port);
		break;
	case IPPROTO_TCP:
		l2pkt_l4write_2(l2pkt, offsetof(struct tcphdr, th_sport), port);
		break;
	default:
		return -1;
	}

	return 0;
}

int
l2pkt_dstport(struct l2pkt *l2pkt, uint16_t port)
{
	uint8_t proto = l2pkt_getl4protocol(l2pkt);

	switch (proto) {
	case IPPROTO_UDP:
		l2pkt_l4write_2(l2pkt, offsetof(struct udphdr, uh_dport), port);
		break;
	case IPPROTO_TCP:
		l2pkt_l4write_2(l2pkt, offsetof(struct tcphdr, th_dport), port);
		break;
	default:
		return -1;
	}

	return 0;
}

int
l2pkt_tcpseq(struct l2pkt *l2pkt, uint32_t seq)
{
	return l2pkt_l4write_4(l2pkt, offsetof(struct tcphdr, th_seq), seq);
}

int
l2pkt_tcpack(struct l2pkt *l2pkt, uint32_t ack)
{
	return l2pkt_l4write_4(l2pkt, offsetof(struct tcphdr, th_ack), ack);
}

int
l2pkt_tcpflags(struct l2pkt *l2pkt, uint8_t flags)
{
	return l2pkt_l4write_1(l2pkt, offsetof(struct tcphdr, th_flags), flags);
}

int
ip4pkt_tcpwin(struct l2pkt *l2pkt, uint16_t win)
{
	return l2pkt_l4write_2(l2pkt, offsetof(struct tcphdr, th_win), win);
}

int
ip4pkt_tcpurp(struct l2pkt *l2pkt, uint16_t urp)
{
	return l2pkt_l4write_2(l2pkt, offsetof(struct tcphdr, th_urp), urp);
}

#if 0

int
ip4pkt_test_cksum(struct l2pkt *l2pkt, unsigned int maxframelen)
{
	struct ether_header *eh;
	struct ip *ip;
	struct icmp *icmp;
	struct udphdr *udp;
	struct tcphdr *tcp;
	unsigned int iplen, iphdrlen, protolen;

	if (maxframelen < sizeof(struct ether_header)) {
		fprintf(stderr, "packet buffer too short. cannot access ether header\n");
		return -1;
	}
	maxframelen -= sizeof(struct ether_header);

	eh = (struct ether_header *)buf;
	if (eh->ether_type != htons(ETHERTYPE_IP)) {
		fprintf(stderr, "ether header is not ETHERTYPE_IP\n");
		return -0x0800;
	}

	if (maxframelen < sizeof(struct ip)) {
		fprintf(stderr, "packet buffer too short. cannot access IP header\n");
		return -1;
	}

	ip = (struct ip *)(eh + 1);
	if (ip->ip_v != IPVERSION) {
		fprintf(stderr, "IP header is not IPv4\n");
		return -1;
	}

	iphdrlen = ip->ip_hl * 4;
	if (in_cksum(0, (char *)ip, ip->ip_hl * 4) != 0) {
		fprintf(stderr, "IP header checksum error\n");
		return -IPPROTO_IPV4;
	}

	iplen = ntohs(ip->ip_len);
	protolen = iplen - iphdrlen;

	if (maxframelen < iphdrlen) {
		fprintf(stderr, "packet buffer too short. cannot access protocol header\n");
		return -1;
	}
	maxframelen -= iphdrlen;

	if (maxframelen < protolen) {
		fprintf(stderr, "packet buffer too short. cannot access protocol data\n");
		return -1;
	}

	switch (ip->ip_p) {
	case IPPROTO_ICMP:
		icmp = (struct icmp *)((char *)ip + iphdrlen);
		if (in4_cksum(ip->ip_src, ip->ip_dst, IPPROTO_ICMP,
		    (char *)icmp, protolen) != 0) {
			fprintf(stderr, "ICMP checksum error\n");
			return -IPPROTO_ICMP;
		}
		break;

	case IPPROTO_UDP:
		udp = (struct udphdr *)((char *)ip + iphdrlen);
		if (protolen < ntohs(udp->uh_ulen)) {
			fprintf(stderr, "UDP packet is greater than IP packet\n");
			return -IPPROTO_ICMP;
		}
		if (in4_cksum(ip->ip_src, ip->ip_dst, IPPROTO_UDP,
		    (char *)udp, protolen) != 0) {
			fprintf(stderr, "UDP checksum error\n");
			return -IPPROTO_ICMP;
		}
		break;

	case IPPROTO_TCP:
		tcp = (struct tcphdr *)((char *)ip + iphdrlen);
		if (in4_cksum(ip->ip_src, ip->ip_dst, IPPROTO_TCP,
		    (char *)tcp, protolen) != 0) {
			fprintf(stderr, "TCP checksum error\n");
			return -IPPROTO_TCP;
		}
		break;

	default:
		return -99999;	/* protocol not supported */
	}

	return 0;
}


#endif

