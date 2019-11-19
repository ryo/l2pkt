#ifndef _TOEPLITZ_HASH_
#define _TOEPLITZ_HASH_

#define RSSKEY_SIZE	40
extern uint8_t rsskey[RSSKEY_SIZE];

uint32_t toeplitz_hash(const uint8_t *, size_t, ...);

#endif /* _TOEPLITZ_HASH_ */
