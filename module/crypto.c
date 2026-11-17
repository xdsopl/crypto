/*
WebAssembly crypto module for digital signing based on Ed25519 and BLAKE2B

Copyright 2024 Ahmet Inan <xdsopl@gmail.com>
*/

#include <string.h>
#include "blake2.h"
#include "ge25519.h"

#define MLEN_MAX (1 << 23)

__attribute__((visibility("default")))
unsigned char digest[64];
__attribute__((visibility("default")))
unsigned char private_key[32];
__attribute__((visibility("default")))
unsigned char fingerprint[32];
__attribute__((visibility("default")))
unsigned char signature[64];
__attribute__((visibility("default")))
unsigned char message[MLEN_MAX];

__attribute__((visibility("default")))
int digest_message(int mlen, int dlen)
{
	blake2b_state state;
	if (mlen < 1 || mlen > MLEN_MAX)
		return 1;
	if (dlen < 1 || dlen > 64)
		return 1;
	blake2b_init(&state, dlen);
	blake2b_update(&state, message, mlen);
	blake2b_final(&state, digest, dlen);
	return 0;
}

__attribute__((visibility("default")))
int create_signature(int mlen)
{
	unsigned char az[64];
	unsigned char nonce[64];
	unsigned char hram[64];
	sc25519 sck, scs, scsk;
	ge25519 ger;
	blake2b_state state;
	if (mlen < 1 || mlen > MLEN_MAX)
		return 1;
	blake2b_init(&state, 64);
	blake2b_update(&state, private_key, 32);
	blake2b_final(&state, az, 64);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	sc25519_from32bytes(&scsk, az);
	ge25519_scalarmult_base(&ger, &scsk);
	ge25519_pack(fingerprint, &ger);
	blake2b_init(&state, 64);
	blake2b_update(&state, az+32, 32);
	blake2b_update(&state, message, mlen);
	blake2b_final(&state, nonce, 64);
	sc25519_from64bytes(&sck, nonce);
	ge25519_scalarmult_base(&ger, &sck);
	ge25519_pack(signature, &ger);
	blake2b_init(&state, 64);
	blake2b_update(&state, signature, 32);
	blake2b_update(&state, fingerprint, 32);
	blake2b_update(&state, message, mlen);
	blake2b_final(&state, hram, 64);
	sc25519_from64bytes(&scs, hram);
	sc25519_mul(&scs, &scs, &scsk);
	sc25519_add(&scs, &scs, &sck);
	sc25519_to32bytes(signature+32, &scs);
	return 0;
}

__attribute__((visibility("default")))
int create_fingerprint(void)
{
	unsigned char az[64];
	sc25519 scsk;
	ge25519 gepk;
	blake2b_state state;
	blake2b_init(&state, 64);
	blake2b_update(&state, private_key, 32);
	blake2b_final(&state, az, 64);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	sc25519_from32bytes(&scsk, az);
	ge25519_scalarmult_base(&gepk, &scsk);
	ge25519_pack(fingerprint, &gepk);
	return 0;
}

/* check if little-endian 32 byte scalar is less than group order L */
static int scalar_is_canonical(const unsigned char s[32])
{
	static const unsigned char L[32] = {
		0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
		0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
	int i;
	for (i = 31; i >= 0; --i) {
		if (s[i] < L[i])
			return 1;
		if (s[i] > L[i])
			return 0;
	}
	return 0;
}

static int has_small_order(const ge25519 *p)
{
	static const unsigned char Y[5][32] = {
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x26, 0xE8, 0x95, 0x8F, 0xC2, 0xB2, 0x27, 0xB0,
			0x45, 0xC3, 0xF4, 0x89, 0xF2, 0xEF, 0x98, 0xF0,
			0xD5, 0xDF, 0xAC, 0x05, 0xD3, 0xC6, 0x33, 0x39,
			0xB1, 0x38, 0x02, 0x88, 0x6D, 0x53, 0xFC, 0x05 },
		{ 0xC7, 0x17, 0x6A, 0x70, 0x3D, 0x4D, 0xD8, 0x4F,
			0xBA, 0x3C, 0x0B, 0x76, 0x0D, 0x10, 0x67, 0x0F,
			0x2A, 0x20, 0x53, 0xFA, 0x2C, 0x39, 0xCC, 0xC6,
			0x4E, 0xC7, 0xFD, 0x77, 0x92, 0xAC, 0x03, 0x7A },
		{ 0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F } };
	unsigned char y[32];
	int i;
	fe25519_pack(y, &p->y);
	for (i = 0; i < 5; ++i)
		if (!memcmp(y, Y[i], 32))
			return 1;
	return 0;
}

__attribute__((visibility("default")))
int verify_signature(int mlen)
{
	unsigned char hram[64], rcheck[32];
	ge25519 get1, get2;
	sc25519 schram, scs;
	blake2b_state state;
	if (mlen < 1 || mlen > MLEN_MAX)
		return 1;
	if (!scalar_is_canonical(signature+32))
		return 1;
	if (ge25519_unpackneg_vartime(&get1, fingerprint))
		return 1;
	if (has_small_order(&get1))
		return 1;
	sc25519_from32bytes(&scs, signature+32);
	blake2b_init(&state, 64);
	blake2b_update(&state, signature, 32);
	blake2b_update(&state, fingerprint, 32);
	blake2b_update(&state, message, mlen);
	blake2b_final(&state, hram, 64);
	sc25519_from64bytes(&schram, hram);
	ge25519_double_scalarmult_vartime(&get2, &get1, &schram, &ge25519_base, &scs);
	ge25519_pack(rcheck, &get2);
	return !!memcmp(signature, rcheck, 32);
}
