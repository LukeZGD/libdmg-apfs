/*
 * util.c
 * apfs-tool
 *
 * Checksums, hashes, UUIDs, time and logging helpers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#include "apfs/apfs.h"

int apfs_verbosity = 1;

void apfs_log(int level, const char* fmt, ...) {
	va_list ap;

	if(level > apfs_verbosity)
		return;

	fflush(stdout);
	switch(level) {
		case 0: fputs("error: ", stderr); break;
		case 1: fputs("warning: ", stderr); break;
		default: break;
	}
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	fflush(stderr);
}

const char* apfs_strerror(int err) {
	switch(err) {
		case APFS_OK: return "success";
		case APFS_EIO: return "I/O error";
		case APFS_ECORRUPT: return "file system structure is corrupted";
		case APFS_ENOENT: return "no such file or directory";
		case APFS_EEXIST: return "file exists";
		case APFS_ENOSPC: return "no space left in container";
		case APFS_ENOTDIR: return "not a directory";
		case APFS_EISDIR: return "is a directory";
		case APFS_ENOTEMPTY: return "directory not empty";
		case APFS_EINVAL: return "invalid argument";
		case APFS_EROFS: return "read-only file system";
		case APFS_ENOMEM: return "out of memory";
		case APFS_EUNSUPP: return "unsupported feature";
		case APFS_ENAMETOOLONG: return "file name too long";
		case APFS_ELOOP: return "too many levels of symbolic links";
		case APFS_ERANGE: return "value out of range";
		case APFS_EBUSY: return "resource busy";
		case APFS_EXDEV: return "cross-volume operation";
		default: return "unknown error";
	}
}

void* apfs_malloc(size_t size) {
	void* p = malloc(size ? size : 1);
	if(!p) {
		fprintf(stderr, "error: out of memory allocating %lu bytes\n", (unsigned long)size);
		exit(1);
	}
	return p;
}

void* apfs_calloc(size_t n, size_t size) {
	void* p = calloc(n ? n : 1, size ? size : 1);
	if(!p) {
		fprintf(stderr, "error: out of memory allocating %lu bytes\n", (unsigned long)(n * size));
		exit(1);
	}
	return p;
}

void* apfs_realloc(void* p, size_t size) {
	void* r = realloc(p, size ? size : 1);
	if(!r) {
		fprintf(stderr, "error: out of memory allocating %lu bytes\n", (unsigned long)size);
		exit(1);
	}
	return r;
}

char* apfs_strdup(const char* s) {
	size_t len = strlen(s);
	char* r = (char*)apfs_malloc(len + 1);
	memcpy(r, s, len + 1);
	return r;
}

/* Fletcher-64 as used for object checksums: 32-bit little-endian words,
 * sums modulo 2^32 - 1. Returns the value to store in o_cksum. */
uint64_t apfs_fletcher64(const void* data, size_t len) {
	const uint8_t* p = (const uint8_t*)data;
	size_t words = len / 4;
	uint64_t sum1 = 0, sum2 = 0;
	uint64_t c1, c2;

	while(words > 0) {
		size_t batch = words > 1024 ? 1024 : words;
		size_t i;
		for(i = 0; i < batch; i++) {
			sum1 += apfs_get32(p);
			sum2 += sum1;
			p += 4;
		}
		sum1 %= 0xFFFFFFFFULL;
		sum2 %= 0xFFFFFFFFULL;
		words -= batch;
	}

	c1 = 0xFFFFFFFFULL - ((sum1 + sum2) % 0xFFFFFFFFULL);
	c2 = 0xFFFFFFFFULL - ((sum1 + c1) % 0xFFFFFFFFULL);
	return (c2 << 32) | c1;
}

int apfs_obj_verify(const void* obj, size_t size) {
	uint64_t stored = apfs_get64(obj);
	return apfs_fletcher64((const uint8_t*)obj + MAX_CKSUM_SIZE, size - MAX_CKSUM_SIZE) == stored;
}

void apfs_obj_set_cksum(void* obj, size_t size) {
	apfs_put64(obj, apfs_fletcher64((const uint8_t*)obj + MAX_CKSUM_SIZE, size - MAX_CKSUM_SIZE));
}

/* CRC-32C (Castagnoli), reflected, without the final inversion. */
static uint32_t crc32c_table[256];
static int crc32c_ready = 0;

static void crc32c_init(void) {
	uint32_t i, j;
	for(i = 0; i < 256; i++) {
		uint32_t c = i;
		for(j = 0; j < 8; j++)
			c = (c & 1) ? (c >> 1) ^ 0x82F63B78U : (c >> 1);
		crc32c_table[i] = c;
	}
	crc32c_ready = 1;
}

uint32_t apfs_crc32c(uint32_t crc, const void* data, size_t len) {
	const uint8_t* p = (const uint8_t*)data;
	if(!crc32c_ready)
		crc32c_init();
	while(len--)
		crc = crc32c_table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
	return crc;
}

/* SHA-256 */

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(apfs_sha256_ctx* ctx, const uint8_t* block) {
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h;
	int i;

	for(i = 0; i < 16; i++)
		w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
			((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
	for(i = 16; i < 64; i++) {
		uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

	for(i = 0; i < 64; i++) {
		uint32_t s1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + s1 + ch + sha256_k[i] + w[i];
		uint32_t s0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = s0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void apfs_sha256_init(apfs_sha256_ctx* ctx) {
	ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
	ctx->length = 0;
	ctx->used = 0;
}

void apfs_sha256_update(apfs_sha256_ctx* ctx, const void* data, size_t len) {
	const uint8_t* p = (const uint8_t*)data;
	ctx->length += len;
	if(ctx->used) {
		size_t take = 64 - ctx->used;
		if(take > len)
			take = len;
		memcpy(ctx->buf + ctx->used, p, take);
		ctx->used += (uint32_t)take;
		p += take;
		len -= take;
		if(ctx->used == 64) {
			sha256_block(ctx, ctx->buf);
			ctx->used = 0;
		}
	}
	while(len >= 64) {
		sha256_block(ctx, p);
		p += 64;
		len -= 64;
	}
	if(len) {
		memcpy(ctx->buf, p, len);
		ctx->used = (uint32_t)len;
	}
}

void apfs_sha256_final(apfs_sha256_ctx* ctx, uint8_t digest[32]) {
	uint64_t bits = ctx->length * 8;
	uint8_t pad = 0x80;
	uint8_t zero = 0;
	uint8_t lenbuf[8];
	int i;

	apfs_sha256_update(ctx, &pad, 1);
	while(ctx->used != 56)
		apfs_sha256_update(ctx, &zero, 1);
	for(i = 0; i < 8; i++)
		lenbuf[i] = (uint8_t)(bits >> (56 - i * 8));
	apfs_sha256_update(ctx, lenbuf, 8);

	for(i = 0; i < 8; i++) {
		digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)ctx->state[i];
	}
}

void apfs_sha256(const void* data, size_t len, uint8_t digest[32]) {
	apfs_sha256_ctx ctx;
	apfs_sha256_init(&ctx);
	apfs_sha256_update(&ctx, data, len);
	apfs_sha256_final(&ctx, digest);
}

/* Time in nanoseconds since 1970-01-01 00:00:00 UTC */
uint64_t apfs_time_now(void) {
	const char* fixed = getenv("APFS_TOOL_TIME");
	if(fixed && *fixed)
		return strtoull(fixed, NULL, 0);
#ifdef _WIN32
	{
		FILETIME ft;
		uint64_t t;
		GetSystemTimeAsFileTime(&ft);
		t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
		/* 100ns ticks since 1601 */
		return (t - 116444736000000000ULL) * 100ULL;
	}
#else
	{
		struct timeval tv;
		gettimeofday(&tv, NULL);
		return (uint64_t)tv.tv_sec * 1000000000ULL + (uint64_t)tv.tv_usec * 1000ULL;
	}
#endif
}

static uint64_t rng_state = 0;

static uint64_t rng_next(void) {
	uint64_t x;
	if(rng_state == 0) {
		rng_state = apfs_time_now() ^ ((uint64_t)(uintptr_t)&rng_state << 16) ^ 0x9E3779B97F4A7C15ULL;
#ifndef _WIN32
		rng_state ^= (uint64_t)getpid() << 32;
#endif
	}
	/* xorshift64* */
	x = rng_state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

void apfs_uuid_generate(uint8_t uuid[16]) {
	int got = 0;
#ifndef _WIN32
	FILE* f = fopen("/dev/urandom", "rb");
	if(f) {
		got = fread(uuid, 1, 16, f) == 16;
		fclose(f);
	}
#endif
	if(!got) {
		uint64_t a = rng_next(), b = rng_next();
		memcpy(uuid, &a, 8);
		memcpy(uuid + 8, &b, 8);
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40;
	uuid[8] = (uuid[8] & 0x3f) | 0x80;
}

void apfs_uuid_format(const uint8_t uuid[16], char out[37]) {
	snprintf(out, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

static int hexval(char c) {
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int apfs_uuid_parse(const char* str, uint8_t uuid[16]) {
	int n = 0;
	while(*str && n < 16) {
		int hi, lo;
		if(*str == '-') {
			str++;
			continue;
		}
		hi = hexval(str[0]);
		lo = hexval(str[1]);
		if(hi < 0 || lo < 0)
			return APFS_EINVAL;
		uuid[n++] = (uint8_t)((hi << 4) | lo);
		str += 2;
	}
	return (n == 16 && *str == '\0') ? APFS_OK : APFS_EINVAL;
}

int apfs_uuid_is_null(const uint8_t uuid[16]) {
	int i;
	for(i = 0; i < 16; i++)
		if(uuid[i])
			return 0;
	return 1;
}

/* SHA-1 (for UDIF nsiz digests) */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(apfs_sha1_ctx* ctx, const uint8_t* p) {
	uint32_t w[80], a, b, c, d, e, t;
	int i;
	for(i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) | ((uint32_t)p[i * 4 + 2] << 8) | p[i * 4 + 3];
	for(i = 16; i < 80; i++)
		w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3]; e = ctx->state[4];
	for(i = 0; i < 80; i++) {
		uint32_t f, k;
		if(i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
		else if(i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
		else if(i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
		else { f = b ^ c ^ d; k = 0xCA62C1D6; }
		t = ROL32(a, 5) + f + e + k + w[i];
		e = d; d = c; c = ROL32(b, 30); b = a; a = t;
	}
	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d; ctx->state[4] += e;
}

void apfs_sha1_init(apfs_sha1_ctx* ctx) {
	ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89; ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476; ctx->state[4] = 0xC3D2E1F0;
	ctx->length = 0;
	ctx->used = 0;
}

void apfs_sha1_update(apfs_sha1_ctx* ctx, const void* data, size_t len) {
	const uint8_t* p = (const uint8_t*)data;
	ctx->length += len;
	if(ctx->used) {
		size_t take = 64 - ctx->used;
		if(take > len)
			take = len;
		memcpy(ctx->buf + ctx->used, p, take);
		ctx->used += (uint32_t)take;
		p += take;
		len -= take;
		if(ctx->used == 64) {
			sha1_block(ctx, ctx->buf);
			ctx->used = 0;
		}
	}
	while(len >= 64) {
		sha1_block(ctx, p);
		p += 64;
		len -= 64;
	}
	if(len) {
		memcpy(ctx->buf, p, len);
		ctx->used = (uint32_t)len;
	}
}

void apfs_sha1_final(apfs_sha1_ctx* ctx, uint8_t digest[20]) {
	uint64_t bits = ctx->length * 8;
	uint8_t pad = 0x80, zero = 0, lenbuf[8];
	int i;
	apfs_sha1_update(ctx, &pad, 1);
	while(ctx->used != 56)
		apfs_sha1_update(ctx, &zero, 1);
	for(i = 0; i < 8; i++)
		lenbuf[i] = (uint8_t)(bits >> (56 - i * 8));
	apfs_sha1_update(ctx, lenbuf, 8);
	for(i = 0; i < 5; i++) {
		digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)ctx->state[i];
	}
}
