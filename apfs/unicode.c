/*
 * unicode.c
 * apfs-tool
 *
 * Filename normalization for APFS: canonical decomposition (NFD), optional
 * full case folding of each decomposed character, and canonical ordering of
 * combining marks. Used for directory record hashes and name comparisons.
 */

#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"
#include "unicode_tables.h"

#define HANGUL_SBASE 0xAC00
#define HANGUL_LBASE 0x1100
#define HANGUL_VBASE 0x1161
#define HANGUL_TBASE 0x11A7
#define HANGUL_LCOUNT 19
#define HANGUL_VCOUNT 21
#define HANGUL_TCOUNT 28
#define HANGUL_NCOUNT (HANGUL_VCOUNT * HANGUL_TCOUNT)
#define HANGUL_SCOUNT (HANGUL_LCOUNT * HANGUL_NCOUNT)

/* Decodes one UTF-8 sequence. Returns its length, or -1 when invalid. */
static int utf8_decode(const uint8_t* s, size_t len, uint32_t* cp) {
	uint32_t c;
	int n, i;

	if(len == 0)
		return -1;
	c = s[0];
	if(c < 0x80) {
		*cp = c;
		return 1;
	} else if((c & 0xE0) == 0xC0) {
		n = 2;
		c &= 0x1F;
	} else if((c & 0xF0) == 0xE0) {
		n = 3;
		c &= 0x0F;
	} else if((c & 0xF8) == 0xF0) {
		n = 4;
		c &= 0x07;
	} else {
		return -1;
	}
	if((size_t)n > len)
		return -1;
	for(i = 1; i < n; i++) {
		if((s[i] & 0xC0) != 0x80)
			return -1;
		c = (c << 6) | (s[i] & 0x3F);
	}
	if((n == 2 && c < 0x80) || (n == 3 && c < 0x800) || (n == 4 && c < 0x10000))
		return -1; /* overlong */
	if(c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
		return -1;
	*cp = c;
	return n;
}

int apfs_utf8_valid(const char* s, size_t len) {
	const uint8_t* p = (const uint8_t*)s;
	while(len > 0) {
		uint32_t cp;
		int n = utf8_decode(p, len, &cp);
		if(n < 0)
			return 0;
		p += n;
		len -= (size_t)n;
	}
	return 1;
}

static const apfs_map_entry_t* map_find(const apfs_map_entry_t* index, int count, uint32_t cp) {
	int lo = 0, hi = count - 1;
	while(lo <= hi) {
		int mid = (lo + hi) / 2;
		if(index[mid].cp == cp)
			return &index[mid];
		if(index[mid].cp < cp)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return NULL;
}

static uint8_t ccc_of(uint32_t cp) {
	int lo = 0, hi = APFS_CCC_RANGES - 1;
	if(cp < 0x300)
		return 0;
	while(lo <= hi) {
		int mid = (lo + hi) / 2;
		if(cp < apfs_ccc_ranges[mid].first)
			hi = mid - 1;
		else if(cp > apfs_ccc_ranges[mid].last)
			lo = mid + 1;
		else
			return apfs_ccc_ranges[mid].ccc;
	}
	return 0;
}

typedef struct {
	uint32_t* cp;
	size_t len;
	size_t cap;
} cpbuf_t;

static void cp_push(cpbuf_t* b, uint32_t c) {
	if(b->len == b->cap) {
		b->cap = b->cap ? b->cap * 2 : 64;
		b->cp = (uint32_t*)apfs_realloc(b->cp, b->cap * sizeof(uint32_t));
	}
	b->cp[b->len++] = c;
}

static void push_folded(cpbuf_t* b, uint32_t c, int case_fold) {
	const apfs_map_entry_t* e;
	int i;

	if(!case_fold) {
		cp_push(b, c);
		return;
	}
	if(c < 0x80) {
		cp_push(b, (c >= 'A' && c <= 'Z') ? c + 32 : c);
		return;
	}
	e = map_find(apfs_cf_index, APFS_CF_ENTRIES, c);
	if(!e) {
		cp_push(b, c);
		return;
	}
	for(i = 0; i < e->len; i++)
		cp_push(b, apfs_cf_pool[e->off + i]);
}

/* Normalizes a UTF-8 string into code points. Returns 0 on success, or -1 if
 * invalid UTF-8 was found; in that case the output holds the normalization of
 * the valid prefix. */
static int normalize(const char* name, size_t len, int case_fold, cpbuf_t* out) {
	const uint8_t* p = (const uint8_t*)name;
	int ret = 0;
	size_t i, start;

	while(len > 0) {
		uint32_t cp;
		int n;

		if(*p == 0)
			break;
		n = utf8_decode(p, len, &cp);
		if(n < 0) {
			ret = -1;
			break;
		}
		p += n;
		len -= (size_t)n;

		if(cp >= HANGUL_SBASE && cp < HANGUL_SBASE + HANGUL_SCOUNT) {
			uint32_t s = cp - HANGUL_SBASE;
			cp_push(out, HANGUL_LBASE + s / HANGUL_NCOUNT);
			cp_push(out, HANGUL_VBASE + (s % HANGUL_NCOUNT) / HANGUL_TCOUNT);
			if(s % HANGUL_TCOUNT)
				cp_push(out, HANGUL_TBASE + s % HANGUL_TCOUNT);
		} else if(cp < 0xC0) {
			push_folded(out, cp, case_fold);
		} else {
			const apfs_map_entry_t* e = map_find(apfs_nfd_index, APFS_NFD_ENTRIES, cp);
			if(!e) {
				push_folded(out, cp, case_fold);
			} else {
				int j;
				for(j = 0; j < e->len; j++)
					push_folded(out, apfs_nfd_pool[e->off + j], case_fold);
			}
		}
	}

	/* Canonical ordering: stable sort of each run of non-starters by class */
	i = 0;
	while(i < out->len) {
		if(ccc_of(out->cp[i]) == 0) {
			i++;
			continue;
		}
		start = i;
		while(i < out->len && ccc_of(out->cp[i]) != 0)
			i++;
		if(i - start > 1) {
			size_t a, b;
			for(a = start + 1; a < i; a++) {
				uint32_t c = out->cp[a];
				uint8_t cc = ccc_of(c);
				b = a;
				while(b > start && ccc_of(out->cp[b - 1]) > cc) {
					out->cp[b] = out->cp[b - 1];
					b--;
				}
				out->cp[b] = c;
			}
		}
	}

	return ret;
}

uint32_t apfs_name_hash(const char* name, size_t len, int case_fold) {
	cpbuf_t buf = { NULL, 0, 0 };
	uint32_t crc = 0xFFFFFFFF;
	size_t i;

	normalize(name, len, case_fold, &buf);
	for(i = 0; i < buf.len; i++) {
		uint8_t le[4];
		apfs_put32(le, buf.cp[i]);
		crc = apfs_crc32c(crc, le, 4);
	}
	free(buf.cp);
	return (crc & 0x3FFFFF) << J_DREC_HASH_SHIFT;
}

int apfs_name_equal(const char* a, size_t alen, const char* b, size_t blen, int norm_insensitive, int case_fold) {
	cpbuf_t na = { NULL, 0, 0 }, nb = { NULL, 0, 0 };
	int ret;

	if(!norm_insensitive && !case_fold) {
		if(alen != blen)
			return 1;
		return memcmp(a, b, alen) != 0;
	}

	normalize(a, alen, case_fold, &na);
	normalize(b, blen, case_fold, &nb);
	if(na.len != nb.len)
		ret = 1;
	else
		ret = na.len ? (memcmp(na.cp, nb.cp, na.len * sizeof(uint32_t)) != 0) : 0;
	free(na.cp);
	free(nb.cp);
	return ret;
}
