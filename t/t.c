#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet6/in6.h>

#include "freebsd_toeplitz.h"
#include "toeplitz_hash.h"

#ifndef timespecsub
#define timespecsub(tsp, usp, vsp)					\
	do {								\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {				\
			(vsp)->tv_sec--;				\
			(vsp)->tv_nsec += 1000000000L;			\
}									\
} while (/* CONSTCOND */ 0)
#endif


unsigned long random_seed;
int benchmark_mode;
int randomcheck_mode;


uint32_t
v_raw_hash(void *b, size_t len)
{
	return toeplitz_vhash(rsskey, sizeof(rsskey),
	    b, len, NULL);
}

uint32_t
v_ip4_hash(struct in_addr *src, struct in_addr *dst)
{
	return toeplitz_vhash(rsskey, sizeof(rsskey),
	    src, sizeof(*src),
	    dst, sizeof(*dst),
	    NULL);
}

uint32_t
v_tcp4_hash(struct in_addr *src, struct in_addr *dst, uint16_t *sport, uint16_t *dport)
{
	return toeplitz_vhash(rsskey, sizeof(rsskey),
	    src, sizeof(*src),
	    dst, sizeof(*dst),
	    sport, sizeof(*sport),
	    dport, sizeof(*dport),
	    NULL);
}

uint32_t
v_ip6_hash(struct in6_addr *src, struct in6_addr *dst)
{
	return toeplitz_vhash(rsskey, sizeof(rsskey),
	    src, sizeof(*src),
	    dst, sizeof(*dst),
	    NULL);
}

uint32_t
v_tcp6_hash(struct in6_addr *src, struct in6_addr *dst, uint16_t *sport, uint16_t *dport)
{
	return toeplitz_vhash(rsskey, sizeof(rsskey),
	    src, sizeof(*src),
	    dst, sizeof(*dst),
	    sport, sizeof(*sport),
	    dport, sizeof(*dport),
	    NULL);
}


uint32_t
fbsd_raw_hash(void *b, size_t len)
{
	return toeplitz_hash(sizeof(rsskey), rsskey,
	    len, b);
}

uint32_t
fbsd_ip4_hash(struct in_addr *src, struct in_addr *dst)
{
	uint8_t tmpbuf[sizeof(*src) + sizeof(*dst)];

	memcpy(tmpbuf + 0,            src, sizeof(*src));
	memcpy(tmpbuf + sizeof(*src), dst, sizeof(*dst));

	return toeplitz_hash(sizeof(rsskey), rsskey,
	    sizeof(tmpbuf), tmpbuf);
}

uint32_t
fbsd_tcp4_hash(struct in_addr *src, struct in_addr *dst, uint16_t *sport, uint16_t *dport)
{
	uint8_t tmpbuf[sizeof(*src) + sizeof(*dst) + sizeof(*sport) + sizeof(*dport)];

	memcpy(tmpbuf + 0,                                            src,   sizeof(*src));
	memcpy(tmpbuf + sizeof(*src),                                 dst,   sizeof(*dst));
	memcpy(tmpbuf + sizeof(*src) + sizeof(*dst),                  sport, sizeof(*sport));
	memcpy(tmpbuf + sizeof(*src) + sizeof(*dst) + sizeof(*sport), dport, sizeof(*dport));

	return toeplitz_hash(sizeof(rsskey), rsskey,
	    sizeof(tmpbuf), tmpbuf);
}

uint32_t
fbsd_ip6_hash(struct in6_addr *src, struct in6_addr *dst)
{
	uint8_t tmpbuf[sizeof(*src) + sizeof(*dst)];

	memcpy(tmpbuf + 0,            src, sizeof(*src));
	memcpy(tmpbuf + sizeof(*src), dst, sizeof(*dst));

	return toeplitz_hash(sizeof(rsskey), rsskey,
	    sizeof(tmpbuf), tmpbuf);
}

uint32_t
fbsd_tcp6_hash(struct in6_addr *src, struct in6_addr *dst, uint16_t *sport, uint16_t *dport)
{
	uint8_t tmpbuf[sizeof(*src) + sizeof(*dst) + sizeof(*sport) + sizeof(*dport)];

	memcpy(tmpbuf + 0,                                            src,   sizeof(*src));
	memcpy(tmpbuf + sizeof(*src),                                 dst,   sizeof(*dst));
	memcpy(tmpbuf + sizeof(*src) + sizeof(*dst),                  sport, sizeof(*sport));
	memcpy(tmpbuf + sizeof(*src) + sizeof(*dst) + sizeof(*sport), dport, sizeof(*dport));

	return toeplitz_hash(sizeof(rsskey), rsskey,
	    sizeof(tmpbuf), tmpbuf);
}

void *
memset_rand(void *b, size_t len)
{
	char *p = b;

	for (; len != 0; len--)
		*p++ = random();
	return b;
}




#define NVERSION	2

struct {
	const char *version;
	uint32_t (*raw_hash)(void *b, size_t len);
	uint32_t (*ip4_hash)(struct in_addr *, struct in_addr *);
	uint32_t (*tcp4_hash)(struct in_addr *, struct in_addr *, uint16_t *, uint16_t *);
	uint32_t (*ip6_hash)(struct in6_addr *, struct in6_addr *);
	uint32_t (*tcp6_hash)(struct in6_addr *, struct in6_addr *, uint16_t *, uint16_t *);
} hashfuncs[NVERSION] = {
	{
		.version = "freebsd",
		.raw_hash  = fbsd_raw_hash,
		.ip4_hash  = fbsd_ip4_hash,
		.tcp4_hash = fbsd_tcp4_hash,
		.ip6_hash  = fbsd_ip6_hash,
		.tcp6_hash = fbsd_tcp6_hash,
	},
	{
		.version = "vhash",
		.raw_hash  = v_raw_hash,
		.ip4_hash  = v_ip4_hash,
		.tcp4_hash = v_tcp4_hash,
		.ip6_hash  = v_ip6_hash,
		.tcp6_hash = v_tcp6_hash,
	},
};


void
random_pattern_test(void)
{
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct tcphdr *tcp4;
	struct tcphdr *tcp6;
	uint32_t hash[NVERSION];
	int n, rand_off, rand_len;

	char data[512];	/* XXX */

	for (unsigned long nloop = 0; ; nloop++) {
		fprintf(stderr, "random pattern test %lu\r", nloop);

		memset_rand(data, sizeof(data));

		rand_off = rand() % 128;
		rand_len = rand() % (RSSKEY_SIZE - 4);

		ip  = (void *)data + rand_off;
		ip6 = (void *)data + rand_off;
		tcp4 = (struct tcphdr *)(ip + 1);
		tcp6 = (struct tcphdr *)(ip6 + 1);


		for (n = 0; n < NVERSION; n++) {
			hash[n] = hashfuncs[n].raw_hash(data, rand_len);
			if (hash[n] != hash[0]) {
				fprintf(stderr, "The result of 'raw_hash' of %s (0x%08x) is different from %s (0x%08x)\n",
				    hashfuncs[n].version, hash[n], hashfuncs[0].version, hash[0]);
				return;
			}
		}

		for (n = 0; n < NVERSION; n++) {
			hash[n] = hashfuncs[n].ip4_hash(&ip->ip_src, &ip->ip_dst);
			if (hash[n] != hash[0]) {
				fprintf(stderr, "The result of 'ip4_hash' of %s (0x%08x) is different from %s (0x%08x)\n",
				    hashfuncs[n].version, hash[n], hashfuncs[0].version, hash[0]);
				return;
			}
		}

		for (n = 0; n < NVERSION; n++) {
			hash[n] = hashfuncs[n].tcp4_hash(&ip->ip_src, &ip->ip_dst, &tcp4->th_sport, &tcp4->th_dport);
			if (hash[n] != hash[0]) {
				fprintf(stderr, "The result of 'tcp4_hash' of %s (0x%08x) is different from %s (0x%08x)\n",
				    hashfuncs[n].version, hash[n], hashfuncs[0].version, hash[0]);
				return;
			}
		}

		for (n = 0; n < NVERSION; n++) {
			hash[n] = hashfuncs[n].ip6_hash(&ip6->ip6_src, &ip6->ip6_dst);
			if (hash[n] != hash[0]) {
				fprintf(stderr, "The result of 'ip6_hash' of %s (0x%08x) is different from %s (0x%08x)\n",
				    hashfuncs[n].version, hash[n], hashfuncs[0].version, hash[0]);
				return;
			}
		}

		for (n = 0; n < NVERSION; n++) {
			hash[n] = hashfuncs[n].tcp6_hash(&ip6->ip6_src, &ip6->ip6_dst, &tcp6->th_sport, &tcp6->th_dport);
			if (hash[n] != hash[0]) {
				fprintf(stderr, "The result of 'tcp6_hash' of %s (0x%08x) is different from %s (0x%08x)\n",
				    hashfuncs[n].version, hash[n], hashfuncs[0].version, hash[0]);
				return;
			}
		}

		memset_rand(rsskey, sizeof(rsskey));
	}

	fprintf(stderr, "\n");
}

void
show_result(const char *title, int nloop, struct timespec *begin, struct timespec *end)
{
	struct timespec elapsed;
	double elapsed_f;
	static double ntimes = 0;

	timespecsub(end, begin, &elapsed);
	elapsed_f = elapsed.tv_sec + elapsed.tv_nsec / 1000000000.0;

	printf("%-32s %4llu.%09lu sec, ",
	    title, (unsigned long long)elapsed.tv_sec, elapsed.tv_nsec);
	printf(" %15.05f times/sec,  ",
	    nloop / elapsed_f);

	if (ntimes == 0) {
		ntimes = nloop / elapsed_f;
		printf("100.00%% (*standard)\n");
	} else {
		printf("%6.02f%%\n", 100.0 * (nloop / elapsed_f) / ntimes);
	}
}

void
benchmark_test(long long nloop)
{
	struct timespec begin, end;
#define BENCHMARK_BEGIN		clock_gettime(CLOCK_MONOTONIC, &begin)
#define BENCHMARK_END		clock_gettime(CLOCK_MONOTONIC, &end)
#define BENCHMARK_RESULT(t)	show_result(t, nloop, &begin, &end)
	long long n;
	int i, v;

	char data[512];

	memset_rand(data, sizeof(data));
	memset_rand(rsskey, sizeof(rsskey));

	for (i = 0; i < 3; i++) {
		for (v = 0; v < NVERSION; v++) {
			BENCHMARK_BEGIN;

			for (n = nloop; n != 0; n--) {
				hashfuncs[v].raw_hash(data,       RSSKEY_SIZE - 4);
				hashfuncs[v].raw_hash(data + 128, 8);
				hashfuncs[v].raw_hash(data + 128, 12);
				hashfuncs[v].raw_hash(data + 192, 32);
				hashfuncs[v].raw_hash(data + 256, 36);
			}

			BENCHMARK_END;
			BENCHMARK_RESULT(hashfuncs[v].version);
		}
	}
}



void
usage(void)
{
	printf("usage: t [options]\n");
	printf("	-s #	set random seed (default: PID)\n");
	printf("\n");
	printf("	-b	benchmark mode (default)\n");
	printf("	-r	random check mode\n");
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch;
	long long nloop = 1000000LL;

	while ((ch = getopt(argc, argv, "bn:s:r")) != -1) {
		switch (ch) {
		case 'b':
			benchmark_mode = 1;
			break;
		case 'n':
			nloop = strtol(optarg, NULL, 10);
			break;
		case 's':
			random_seed = strtol(optarg, NULL, 10);
			break;
		case 'r':
			randomcheck_mode = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	random_seed = getpid();

	fprintf(stderr, "srandom(%ld)\n", random_seed);
	srandom(random_seed);

	if (randomcheck_mode) {
		fprintf(stderr, "random test mode\n");
		random_pattern_test();
	} else {
		fprintf(stderr, "benchmark mode: %lld loops\n", nloop);
		benchmark_test(nloop);
	}

	return 0;
}
