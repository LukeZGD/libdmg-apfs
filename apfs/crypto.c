/*
 * crypto.c
 * apfs-tool
 *
 * The ciphers, MACs and key derivations of encrypted disk images and
 * archives: AES (CBC and CTR), triple DES, HMAC, PBKDF2 and HKDF.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"

/* AES, with tables computed on first use */

static uint8_t aes_sbox[256], aes_inv_sbox[256];
static uint32_t aes_te[4][256], aes_td[4][256];
static int aes_ready;

#define ROTL8(x, n) ((uint8_t)(((x) << (n)) | ((x) >> (8 - (n)))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define GET32(p) (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | ((uint32_t)(p)[2] << 8) | (uint32_t)(p)[3])
#define PUT32(p, v) ((p)[0] = (uint8_t)((v) >> 24), (p)[1] = (uint8_t)((v) >> 16), (p)[2] = (uint8_t)((v) >> 8), (p)[3] = (uint8_t)(v))

static uint8_t xtime(uint8_t x) {
	return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static uint8_t gmul(uint8_t a, uint8_t b) {
	uint8_t r = 0;
	while(b) {
		if(b & 1)
			r ^= a;
		a = xtime(a);
		b >>= 1;
	}
	return r;
}

static void aes_init(void) {
	uint8_t p = 1, q = 1;
	int i;

	/* p runs through the powers of 3 and q through their inverses, so the
	 * affine map of q gives the S-box entry of p */
	do {
		p = (uint8_t)(p ^ xtime(p));
		q ^= (uint8_t)(q << 1);
		q ^= (uint8_t)(q << 2);
		q ^= (uint8_t)(q << 4);
		if(q & 0x80)
			q ^= 0x09;
		aes_sbox[p] = (uint8_t)(q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4) ^ 0x63);
	} while(p != 1);
	aes_sbox[0] = 0x63;
	for(i = 0; i < 256; i++)
		aes_inv_sbox[aes_sbox[i]] = (uint8_t)i;
	for(i = 0; i < 256; i++) {
		uint8_t s = aes_sbox[i], v = aes_inv_sbox[i];
		uint32_t e = ((uint32_t)xtime(s) << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | (uint32_t)(xtime(s) ^ s);
		uint32_t d = ((uint32_t)gmul(v, 14) << 24) | ((uint32_t)gmul(v, 9) << 16) | ((uint32_t)gmul(v, 13) << 8) | (uint32_t)gmul(v, 11);
		aes_te[0][i] = e;
		aes_te[1][i] = ROR32(e, 8);
		aes_te[2][i] = ROR32(e, 16);
		aes_te[3][i] = ROR32(e, 24);
		aes_td[0][i] = d;
		aes_td[1][i] = ROR32(d, 8);
		aes_td[2][i] = ROR32(d, 16);
		aes_td[3][i] = ROR32(d, 24);
	}
	aes_ready = 1;
}

static uint32_t sub_word(uint32_t w) {
	return ((uint32_t)aes_sbox[w >> 24] << 24) | ((uint32_t)aes_sbox[(w >> 16) & 0xff] << 16) |
		((uint32_t)aes_sbox[(w >> 8) & 0xff] << 8) | (uint32_t)aes_sbox[w & 0xff];
}

int apfs_aes_init(apfs_aes_ctx* ctx, const uint8_t* key, size_t len) {
	int nk = (int)(len / 4), i, n;
	uint8_t rcon = 1;

	if(len != 16 && len != 24 && len != 32)
		return APFS_EINVAL;
	if(!aes_ready)
		aes_init();
	ctx->rounds = nk + 6;
	n = 4 * (ctx->rounds + 1);
	for(i = 0; i < nk; i++)
		ctx->ek[i] = GET32(key + 4 * i);
	for(i = nk; i < n; i++) {
		uint32_t t = ctx->ek[i - 1];
		if(i % nk == 0) {
			t = sub_word((t << 8) | (t >> 24)) ^ ((uint32_t)rcon << 24);
			rcon = xtime(rcon);
		} else if(nk > 6 && i % nk == 4) {
			t = sub_word(t);
		}
		ctx->ek[i] = ctx->ek[i - nk] ^ t;
	}
	/* the equivalent inverse cipher: round keys in reverse order, with
	 * InvMixColumns applied to all but the first and the last */
	for(i = 0; i < n; i += 4)
		memcpy(ctx->dk + i, ctx->ek + n - 4 - i, 4 * sizeof(uint32_t));
	for(i = 4; i < n - 4; i++) {
		uint32_t w = ctx->dk[i];
		ctx->dk[i] = aes_td[0][aes_sbox[w >> 24]] ^ aes_td[1][aes_sbox[(w >> 16) & 0xff]] ^
			aes_td[2][aes_sbox[(w >> 8) & 0xff]] ^ aes_td[3][aes_sbox[w & 0xff]];
	}
	return APFS_OK;
}

void apfs_aes_encrypt(const apfs_aes_ctx* ctx, const uint8_t in[16], uint8_t out[16]) {
	const uint32_t* rk = ctx->ek;
	uint32_t s0 = GET32(in) ^ rk[0], s1 = GET32(in + 4) ^ rk[1], s2 = GET32(in + 8) ^ rk[2], s3 = GET32(in + 12) ^ rk[3];
	uint32_t t0, t1, t2, t3;
	int r;

	for(r = 1; r < ctx->rounds; r++) {
		rk += 4;
		t0 = aes_te[0][s0 >> 24] ^ aes_te[1][(s1 >> 16) & 0xff] ^ aes_te[2][(s2 >> 8) & 0xff] ^ aes_te[3][s3 & 0xff] ^ rk[0];
		t1 = aes_te[0][s1 >> 24] ^ aes_te[1][(s2 >> 16) & 0xff] ^ aes_te[2][(s3 >> 8) & 0xff] ^ aes_te[3][s0 & 0xff] ^ rk[1];
		t2 = aes_te[0][s2 >> 24] ^ aes_te[1][(s3 >> 16) & 0xff] ^ aes_te[2][(s0 >> 8) & 0xff] ^ aes_te[3][s1 & 0xff] ^ rk[2];
		t3 = aes_te[0][s3 >> 24] ^ aes_te[1][(s0 >> 16) & 0xff] ^ aes_te[2][(s1 >> 8) & 0xff] ^ aes_te[3][s2 & 0xff] ^ rk[3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}
	rk += 4;
	t0 = sub_word((s0 & 0xff000000) | (s1 & 0xff0000) | (s2 & 0xff00) | (s3 & 0xff)) ^ rk[0];
	t1 = sub_word((s1 & 0xff000000) | (s2 & 0xff0000) | (s3 & 0xff00) | (s0 & 0xff)) ^ rk[1];
	t2 = sub_word((s2 & 0xff000000) | (s3 & 0xff0000) | (s0 & 0xff00) | (s1 & 0xff)) ^ rk[2];
	t3 = sub_word((s3 & 0xff000000) | (s0 & 0xff0000) | (s1 & 0xff00) | (s2 & 0xff)) ^ rk[3];
	PUT32(out, t0); PUT32(out + 4, t1); PUT32(out + 8, t2); PUT32(out + 12, t3);
}

static uint32_t inv_sub_word(uint32_t w) {
	return ((uint32_t)aes_inv_sbox[w >> 24] << 24) | ((uint32_t)aes_inv_sbox[(w >> 16) & 0xff] << 16) |
		((uint32_t)aes_inv_sbox[(w >> 8) & 0xff] << 8) | (uint32_t)aes_inv_sbox[w & 0xff];
}

void apfs_aes_decrypt(const apfs_aes_ctx* ctx, const uint8_t in[16], uint8_t out[16]) {
	const uint32_t* rk = ctx->dk;
	uint32_t s0 = GET32(in) ^ rk[0], s1 = GET32(in + 4) ^ rk[1], s2 = GET32(in + 8) ^ rk[2], s3 = GET32(in + 12) ^ rk[3];
	uint32_t t0, t1, t2, t3;
	int r;

	for(r = 1; r < ctx->rounds; r++) {
		rk += 4;
		t0 = aes_td[0][s0 >> 24] ^ aes_td[1][(s3 >> 16) & 0xff] ^ aes_td[2][(s2 >> 8) & 0xff] ^ aes_td[3][s1 & 0xff] ^ rk[0];
		t1 = aes_td[0][s1 >> 24] ^ aes_td[1][(s0 >> 16) & 0xff] ^ aes_td[2][(s3 >> 8) & 0xff] ^ aes_td[3][s2 & 0xff] ^ rk[1];
		t2 = aes_td[0][s2 >> 24] ^ aes_td[1][(s1 >> 16) & 0xff] ^ aes_td[2][(s0 >> 8) & 0xff] ^ aes_td[3][s3 & 0xff] ^ rk[2];
		t3 = aes_td[0][s3 >> 24] ^ aes_td[1][(s2 >> 16) & 0xff] ^ aes_td[2][(s1 >> 8) & 0xff] ^ aes_td[3][s0 & 0xff] ^ rk[3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}
	rk += 4;
	t0 = inv_sub_word((s0 & 0xff000000) | (s3 & 0xff0000) | (s2 & 0xff00) | (s1 & 0xff)) ^ rk[0];
	t1 = inv_sub_word((s1 & 0xff000000) | (s0 & 0xff0000) | (s3 & 0xff00) | (s2 & 0xff)) ^ rk[1];
	t2 = inv_sub_word((s2 & 0xff000000) | (s1 & 0xff0000) | (s0 & 0xff00) | (s3 & 0xff)) ^ rk[2];
	t3 = inv_sub_word((s3 & 0xff000000) | (s2 & 0xff0000) | (s1 & 0xff00) | (s0 & 0xff)) ^ rk[3];
	PUT32(out, t0); PUT32(out + 4, t1); PUT32(out + 8, t2); PUT32(out + 12, t3);
}

/* len is a multiple of 16; in and out may be the same buffer */
void apfs_aes_cbc_decrypt(const apfs_aes_ctx* ctx, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len) {
	uint8_t prev[16], cur[16];
	size_t i, j;
	memcpy(prev, iv, 16);
	for(i = 0; i + 16 <= len; i += 16) {
		memcpy(cur, in + i, 16);
		apfs_aes_decrypt(ctx, cur, out + i);
		for(j = 0; j < 16; j++)
			out[i + j] ^= prev[j];
		memcpy(prev, cur, 16);
	}
}

void apfs_aes_cbc_encrypt(const apfs_aes_ctx* ctx, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len) {
	uint8_t x[16];
	const uint8_t* prev = iv;
	size_t i, j;
	for(i = 0; i + 16 <= len; i += 16) {
		for(j = 0; j < 16; j++)
			x[j] = in[i + j] ^ prev[j];
		apfs_aes_encrypt(ctx, x, out + i);
		prev = out + i;
	}
}

/* Counter mode with the whole 16-byte block as a big-endian counter */
void apfs_aes_ctr(const apfs_aes_ctx* ctx, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len) {
	uint8_t ctr[16], ks[16];
	size_t i, j;
	int k;
	memcpy(ctr, iv, 16);
	for(i = 0; i < len; i += 16) {
		apfs_aes_encrypt(ctx, ctr, ks);
		for(j = 0; j < 16 && i + j < len; j++)
			out[i + j] = in[i + j] ^ ks[j];
		for(k = 15; k >= 0 && ++ctr[k] == 0; k--)
			;
	}
}

/* Triple DES (EDE with three keys), only to unwrap keys protected by a
 * passphrase */

static const uint8_t des_ip[64] = {
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};
static const uint8_t des_fp[64] = {
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
};
static const uint8_t des_e[48] = {
	32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};
static const uint8_t des_p[32] = {
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};
static const uint8_t des_pc1[56] = {
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};
static const uint8_t des_pc2[48] = {
	14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
static const uint8_t des_shifts[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
static const uint8_t des_s[8][64] = {
	{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	  4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
	{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	  0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
	{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	  13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
	{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	  10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
	{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	  4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
	{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	  9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
	{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	  1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
	{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	  7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
};

/* Picks bits of a width-bit value, numbered from 1 at the most significant
 * end as in the DES standard */
static uint64_t des_permute(uint64_t in, const uint8_t* table, int n, int width) {
	uint64_t out = 0;
	int i;
	for(i = 0; i < n; i++)
		out = (out << 1) | ((in >> (width - table[i])) & 1);
	return out;
}

static void des_subkeys(const uint8_t key[8], uint64_t sub[16]) {
	uint64_t k = des_permute(GET32(key) * 0x100000000ULL + GET32(key + 4), des_pc1, 56, 64);
	uint32_t c = (uint32_t)(k >> 28), d = (uint32_t)(k & 0xfffffff);
	int r;
	for(r = 0; r < 16; r++) {
		c = ((c << des_shifts[r]) | (c >> (28 - des_shifts[r]))) & 0xfffffff;
		d = ((d << des_shifts[r]) | (d >> (28 - des_shifts[r]))) & 0xfffffff;
		sub[r] = des_permute(((uint64_t)c << 28) | d, des_pc2, 48, 56);
	}
}

static uint64_t des_block(const uint64_t sub[16], uint64_t block, int decrypt) {
	uint64_t b = des_permute(block, des_ip, 64, 64);
	uint32_t l = (uint32_t)(b >> 32), r = (uint32_t)b;
	int i, j;
	for(i = 0; i < 16; i++) {
		uint64_t e = des_permute(r, des_e, 48, 32) ^ sub[decrypt ? 15 - i : i];
		uint32_t s = 0, t;
		for(j = 0; j < 8; j++) {
			unsigned six = (unsigned)(e >> (42 - 6 * j)) & 0x3f;
			s = (s << 4) | des_s[j][((six & 0x20) | ((six & 1) << 4)) | ((six >> 1) & 0xf)];
		}
		t = l ^ (uint32_t)des_permute(s, des_p, 32, 32);
		l = r;
		r = t;
	}
	return des_permute(((uint64_t)r << 32) | l, des_fp, 64, 64);
}

/* Decrypts in place and checks the PKCS#7 padding; returns the length
 * without it, or a negative value */
int apfs_des3_cbc_decrypt(const uint8_t key[24], const uint8_t iv[8], uint8_t* data, size_t len) {
	uint64_t k1[16], k2[16], k3[16];
	uint64_t prev = GET32(iv) * 0x100000000ULL + GET32(iv + 4);
	size_t i;
	unsigned pad;

	if(!len || len % 8)
		return APFS_EINVAL;
	des_subkeys(key, k1);
	des_subkeys(key + 8, k2);
	des_subkeys(key + 16, k3);
	for(i = 0; i < len; i += 8) {
		uint64_t c = GET32(data + i) * 0x100000000ULL + GET32(data + i + 4);
		uint64_t p = des_block(k1, des_block(k2, des_block(k3, c, 1), 0), 1) ^ prev;
		PUT32(data + i, (uint32_t)(p >> 32));
		PUT32(data + i + 4, (uint32_t)p);
		prev = c;
	}
	pad = data[len - 1];
	if(pad == 0 || pad > 8)
		return APFS_EINVAL;
	for(i = len - pad; i < len; i++)
		if(data[i] != pad)
			return APFS_EINVAL;
	return (int)(len - pad);
}

/* HMAC */

void apfs_hmac_sha256_init(apfs_hmac_sha256_ctx* ctx, const uint8_t* key, size_t len) {
	uint8_t k[64], pad[64];
	int i;
	memset(k, 0, sizeof(k));
	if(len > 64)
		apfs_sha256(key, len, k);
	else if(len)
		memcpy(k, key, len);
	for(i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x36;
	apfs_sha256_init(&ctx->inner);
	apfs_sha256_update(&ctx->inner, pad, 64);
	for(i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x5c;
	apfs_sha256_init(&ctx->outer);
	apfs_sha256_update(&ctx->outer, pad, 64);
}

void apfs_hmac_sha256_update(apfs_hmac_sha256_ctx* ctx, const void* data, size_t len) {
	apfs_sha256_update(&ctx->inner, data, len);
}

void apfs_hmac_sha256_final(apfs_hmac_sha256_ctx* ctx, uint8_t mac[32]) {
	uint8_t h[32];
	apfs_sha256_final(&ctx->inner, h);
	apfs_sha256_update(&ctx->outer, h, 32);
	apfs_sha256_final(&ctx->outer, mac);
}

void apfs_hmac_sha256(const uint8_t* key, size_t klen, const void* data, size_t len, uint8_t mac[32]) {
	apfs_hmac_sha256_ctx ctx;
	apfs_hmac_sha256_init(&ctx, key, klen);
	apfs_hmac_sha256_update(&ctx, data, len);
	apfs_hmac_sha256_final(&ctx, mac);
}

/* The SHA-1 states after the padded key, which every MAC with that key
 * starts from */
typedef struct {
	apfs_sha1_ctx inner, outer;
} hmac_sha1_ctx;

static void hmac_sha1_init(hmac_sha1_ctx* ctx, const uint8_t* key, size_t len) {
	uint8_t k[64], pad[64];
	int i;
	memset(k, 0, sizeof(k));
	if(len > 64) {
		apfs_sha1_ctx h;
		apfs_sha1_init(&h);
		apfs_sha1_update(&h, key, len);
		apfs_sha1_final(&h, k);
	} else if(len) {
		memcpy(k, key, len);
	}
	for(i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x36;
	apfs_sha1_init(&ctx->inner);
	apfs_sha1_update(&ctx->inner, pad, 64);
	for(i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x5c;
	apfs_sha1_init(&ctx->outer);
	apfs_sha1_update(&ctx->outer, pad, 64);
}

static void hmac_sha1(const hmac_sha1_ctx* key, const void* data, size_t len, uint8_t mac[20]) {
	hmac_sha1_ctx c = *key;
	uint8_t h[20];
	apfs_sha1_update(&c.inner, data, len);
	apfs_sha1_final(&c.inner, h);
	apfs_sha1_update(&c.outer, h, 20);
	apfs_sha1_final(&c.outer, mac);
}

void apfs_hmac_sha1(const uint8_t* key, size_t klen, const void* data, size_t len, uint8_t mac[20]) {
	hmac_sha1_ctx ctx;
	hmac_sha1_init(&ctx, key, klen);
	hmac_sha1(&ctx, data, len, mac);
}

/* Key derivation */

void apfs_pbkdf2_sha1(const char* pass, size_t plen, const uint8_t* salt, size_t slen, uint32_t iterations, uint8_t* out, size_t len) {
	hmac_sha1_ctx key;
	uint8_t* msg = (uint8_t*)apfs_malloc(slen + 4);
	uint32_t block = 1, i;
	hmac_sha1_init(&key, (const uint8_t*)pass, plen);
	memcpy(msg, salt, slen);
	while(len) {
		uint8_t u[20], t[20];
		size_t n = len < 20 ? len : 20, j;
		PUT32(msg + slen, block);
		hmac_sha1(&key, msg, slen + 4, u);
		memcpy(t, u, 20);
		for(i = 1; i < iterations; i++) {
			hmac_sha1(&key, u, 20, u);
			for(j = 0; j < 20; j++)
				t[j] ^= u[j];
		}
		memcpy(out, t, n);
		out += n;
		len -= n;
		block++;
	}
	free(msg);
}

/* An empty salt is the same as a salt of zeros, as RFC 5869 says */
void apfs_hkdf_sha256(const uint8_t* ikm, size_t ilen, const uint8_t* salt, size_t slen, const void* info, size_t nlen, uint8_t* out, size_t len) {
	uint8_t prk[32], t[32];
	uint8_t i = 1;
	size_t tlen = 0;
	apfs_hmac_sha256(salt, slen, ikm, ilen, prk);
	while(len) {
		apfs_hmac_sha256_ctx ctx;
		size_t n = len < 32 ? len : 32;
		apfs_hmac_sha256_init(&ctx, prk, 32);
		apfs_hmac_sha256_update(&ctx, t, tlen);
		apfs_hmac_sha256_update(&ctx, info, nlen);
		apfs_hmac_sha256_update(&ctx, &i, 1);
		apfs_hmac_sha256_final(&ctx, t);
		tlen = 32;
		memcpy(out, t, n);
		out += n;
		len -= n;
		i++;
	}
}
