/*
 * encrypted.c
 * apfs-tool
 *
 * Encrypted disk images. hdiutil's encrypted images (encrcdsa, version 2)
 * encrypt their data in chunks with AES-CBC, each chunk with an IV made by
 * HMAC-SHA1 from its number; the keys are stored wrapped with triple DES
 * under a key derived from the passphrase. Apple Encrypted Archives (AEA1,
 * profile 1) hold their data in segments, each with its own AES-CTR key and
 * HMAC-SHA256 key, derived with HKDF from the archive key.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "apfs/apfs.h"
#include "apfs/encrypted.h"
#include "lzfse.h"

static uint32_t be32(const uint8_t* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const uint8_t* p) {
	return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static uint32_t le32(const uint8_t* p) {
	return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0];
}

static uint64_t le64(const uint8_t* p) {
	return ((uint64_t)le32(p + 4) << 32) | le32(p);
}

static int read_at(AbstractFile* f, uint64_t off, void* buf, size_t len) {
	return f->seek(f, (off_t)off) == 0 && f->read(f, buf, len) == len;
}

static int hex_digit(int c) {
	if(c >= '0' && c <= '9')
		return c - '0';
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int apfs_parse_key(const char* s, uint8_t** key, size_t* len) {
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t n, i, o = 0;
	int is_hex = 1, bits = 0;
	uint32_t acc = 0;
	uint8_t* k;

	if(!strncmp(s, "hex:", 4)) {
		s += 4;
	} else if(!strncmp(s, "base64:", 7)) {
		s += 7;
		is_hex = 0;
	}
	n = strlen(s);
	for(i = 0; is_hex && i < n; i++)
		if(hex_digit(s[i]) < 0)
			is_hex = 0;
	k = (uint8_t*)apfs_malloc(n + 1);
	if(is_hex && n && n % 2 == 0) {
		for(i = 0; i < n; i += 2)
			k[o++] = (uint8_t)((hex_digit(s[i]) << 4) | hex_digit(s[i + 1]));
	} else {
		for(i = 0; i < n && s[i] != '='; i++) {
			const char* p = strchr(b64, s[i]);
			if(!p) {
				free(k);
				return APFS_EINVAL;
			}
			acc = (acc << 6) | (uint32_t)(p - b64);
			bits += 6;
			if(bits >= 8) {
				bits -= 8;
				k[o++] = (uint8_t)(acc >> bits);
			}
		}
	}
	if(!o) {
		free(k);
		return APFS_EINVAL;
	}
	*key = k;
	*len = o;
	return APFS_OK;
}

/* encrcdsa */

#define ENCRCDSA_HEADER 0x4c

struct encrcdsa_info {
	uint8_t* header;              /* everything before the data */
	size_t header_len;
	uint32_t chunk;               /* size of the encrypted chunks */
	int key_bits;
	apfs_aes_ctx aes;
	uint8_t aes_key[32];
	uint8_t hmac_key[20];
};

typedef struct {
	AbstractFile* file;
	encrcdsa_info_t* info;
	uint64_t size;                /* of the decrypted data */
	uint64_t pos;
	uint64_t cached;              /* number of the chunk in buf */
	int have_cached;
	uint8_t* buf;
} encrcdsa_t;

int encrcdsa_probe(AbstractFile* f) {
	uint8_t m[8];
	return read_at(f, 0, m, 8) && !memcmp(m, "encrcdsa", 8);
}

static void chunk_iv(const encrcdsa_info_t* info, uint64_t n, uint8_t iv[16]) {
	uint8_t num[4], mac[20];
	num[0] = (uint8_t)(n >> 24);
	num[1] = (uint8_t)(n >> 16);
	num[2] = (uint8_t)(n >> 8);
	num[3] = (uint8_t)n;
	apfs_hmac_sha1(info->hmac_key, 20, num, 4, mac);
	memcpy(iv, mac, 16);
}

/* A passphrase entry: PBKDF2-SHA1 of the passphrase is a triple DES key
 * that decrypts the AES key, the HMAC key and "CKIE" */
static int unwrap_keys(encrcdsa_info_t* info, const uint8_t* e, uint64_t len, const char* pass) {
	uint8_t dk[24], blob[256];
	uint32_t salt_len, blob_len;
	size_t klen = (size_t)info->key_bits / 8;
	int n;

	if(len < 104)
		return APFS_EINVAL;
	salt_len = be32(e + 12);
	blob_len = be32(e + 100);
	/* PBKDF2, 8-byte IV, 192-bit triple DES */
	if(be32(e) != 103 || salt_len > 32 || be32(e + 48) != 8 || be32(e + 84) != 192 || be32(e + 88) != 17 ||
			blob_len > sizeof(blob) || blob_len % 8 || 104 + (uint64_t)blob_len > len)
		return APFS_EUNSUPP;
	apfs_pbkdf2_sha1(pass, strlen(pass), e + 16, salt_len, be32(e + 8), dk, sizeof(dk));
	memcpy(blob, e + 104, blob_len);
	n = apfs_des3_cbc_decrypt(dk, e + 52, blob, blob_len);
	if(n < (int)(klen + 24) || memcmp(blob + klen + 20, "CKIE", 4) != 0)
		return APFS_EINVAL;
	memcpy(info->aes_key, blob, klen);
	memcpy(info->hmac_key, blob + klen, 20);
	return APFS_OK;
}

static size_t encrcdsa_read(AbstractFile* af, void* data, size_t len) {
	encrcdsa_t* e = (encrcdsa_t*)af->data;
	uint32_t chunk = e->info->chunk;
	size_t done = 0;

	while(done < len && e->pos < e->size) {
		uint64_t n = e->pos / chunk;
		size_t off = (size_t)(e->pos % chunk), take = chunk - off;
		if(!e->have_cached || e->cached != n) {
			uint8_t iv[16];
			if(!read_at(e->file, e->info->header_len + n * chunk, e->buf, chunk))
				break;
			chunk_iv(e->info, n, iv);
			apfs_aes_cbc_decrypt(&e->info->aes, iv, e->buf, e->buf, chunk);
			e->cached = n;
			e->have_cached = 1;
		}
		if(take > len - done)
			take = len - done;
		if(take > e->size - e->pos)
			take = (size_t)(e->size - e->pos);
		memcpy((uint8_t*)data + done, e->buf + off, take);
		done += take;
		e->pos += take;
	}
	return done;
}

static size_t encrypted_write(AbstractFile* af, const void* data, size_t len) {
	(void)af;
	(void)data;
	(void)len;
	return 0;
}

static int encrcdsa_seek(AbstractFile* af, off_t off) {
	((encrcdsa_t*)af->data)->pos = (uint64_t)off;
	return 0;
}

static off_t encrcdsa_tell(AbstractFile* af) {
	return (off_t)((encrcdsa_t*)af->data)->pos;
}

static off_t encrcdsa_length(AbstractFile* af) {
	return (off_t)((encrcdsa_t*)af->data)->size;
}

void encrcdsa_info_free(encrcdsa_info_t* info) {
	if(info) {
		free(info->header);
		free(info);
	}
}

static void encrcdsa_close(AbstractFile* af) {
	encrcdsa_t* e = (encrcdsa_t*)af->data;
	e->file->close(e->file);
	encrcdsa_info_free(e->info);
	free(e->buf);
	free(e);
	free(af);
}

AbstractFile* encrcdsa_open(AbstractFile* f, const uint8_t* key, size_t key_len, const char* passphrase, encrcdsa_info_t** out_info) {
	uint8_t h[ENCRCDSA_HEADER];
	encrcdsa_info_t* info = NULL;
	encrcdsa_t* e;
	AbstractFile* af;
	uint64_t data_off;
	uint32_t nkeys, i;
	int have_keys = 0, have_entry = 0;

	if(!read_at(f, 0, h, sizeof(h)) || memcmp(h, "encrcdsa", 8) != 0 || be32(h + 8) != 2) {
		APFS_ERR("unsupported encrypted image: only version 2 is supported");
		goto fail;
	}
	info = (encrcdsa_info_t*)apfs_calloc(1, sizeof(encrcdsa_info_t));
	info->key_bits = (int)be32(h + 0x18);
	info->chunk = be32(h + 0x34);
	data_off = be64(h + 0x40);
	nkeys = be32(h + 0x48);
	/* AES-128 or AES-256 with HMAC-SHA1 */
	if(be32(h + 0x14) != 0x80000001 || (info->key_bits != 128 && info->key_bits != 256) || be32(h + 0x1c) != 91 ||
			info->chunk < 512 || info->chunk > (1 << 20) || (info->chunk & (info->chunk - 1)) ||
			data_off < sizeof(h) + 20 * (uint64_t)nkeys || data_off > (64 << 20)) {
		APFS_ERR("unsupported encrypted image");
		goto fail;
	}
	info->header_len = (size_t)data_off;
	info->header = (uint8_t*)apfs_malloc(info->header_len);
	if(!read_at(f, 0, info->header, info->header_len)) {
		APFS_ERR("cannot read the header of the encrypted image");
		goto fail;
	}
	if(key) {
		if(key_len != (size_t)info->key_bits / 8 + 20) {
			APFS_ERR("the key of this image has %d bytes: the AES-%d key, then the HMAC-SHA1 key", info->key_bits / 8 + 20, info->key_bits);
			goto fail;
		}
		memcpy(info->aes_key, key, key_len - 20);
		memcpy(info->hmac_key, key + key_len - 20, 20);
		have_keys = 1;
	} else if(passphrase) {
		for(i = 0; i < nkeys && !have_keys; i++) {
			const uint8_t* p = info->header + ENCRCDSA_HEADER + 20 * i;
			uint64_t off = be64(p + 4), len = be64(p + 12);
			if(be32(p) != 1 || off > info->header_len || len > info->header_len - off)
				continue;
			have_entry = 1;
			have_keys = unwrap_keys(info, info->header + off, len, passphrase) == APFS_OK;
		}
		if(!have_keys) {
			APFS_ERR(have_entry ? "wrong passphrase" : "the image has no passphrase; give its key with -k");
			goto fail;
		}
	} else {
		APFS_ERR("the image is encrypted: give its passphrase with -p or its key with -k");
		goto fail;
	}
	apfs_aes_init(&info->aes, info->aes_key, (size_t)info->key_bits / 8);
	if(out_info) {
		encrcdsa_info_t* copy = (encrcdsa_info_t*)apfs_malloc(sizeof(encrcdsa_info_t));
		*copy = *info;
		copy->header = (uint8_t*)apfs_malloc(info->header_len);
		memcpy(copy->header, info->header, info->header_len);
		*out_info = copy;
	}

	e = (encrcdsa_t*)apfs_calloc(1, sizeof(encrcdsa_t));
	e->file = f;
	e->info = info;
	e->size = be64(h + 0x38);
	e->buf = (uint8_t*)apfs_malloc(info->chunk);
	af = (AbstractFile*)apfs_calloc(1, sizeof(AbstractFile));
	af->data = e;
	af->read = encrcdsa_read;
	af->write = encrypted_write;
	af->seek = encrcdsa_seek;
	af->tell = encrcdsa_tell;
	af->getLength = encrcdsa_length;
	af->close = encrcdsa_close;
	af->type = AbstractFileTypeFile;
	return af;

fail:
	encrcdsa_info_free(info);
	f->close(f);
	return NULL;
}

int encrcdsa_save(const encrcdsa_info_t* info, FILE* plain, uint64_t len, FILE* out) {
	uint8_t* header = (uint8_t*)apfs_malloc(info->header_len);
	uint8_t* buf = (uint8_t*)apfs_malloc(info->chunk);
	uint64_t n;
	int ok, i;

	memcpy(header, info->header, info->header_len);
	for(i = 0; i < 8; i++)
		header[0x38 + i] = (uint8_t)(len >> (56 - 8 * i));
	ok = fwrite(header, 1, info->header_len, out) == info->header_len && fseeko(plain, 0, SEEK_SET) == 0;
	for(n = 0; ok && n * info->chunk < len; n++) {
		uint8_t iv[16];
		size_t take = len - n * info->chunk < info->chunk ? (size_t)(len - n * info->chunk) : info->chunk;
		memset(buf + take, 0, info->chunk - take);
		ok = fread(buf, 1, take, plain) == take;
		chunk_iv(info, n, iv);
		apfs_aes_cbc_encrypt(&info->aes, iv, buf, buf, info->chunk);
		ok = ok && fwrite(buf, 1, info->chunk, out) == info->chunk;
	}
	free(buf);
	free(header);
	return ok ? APFS_OK : APFS_EIO;
}

int encrcdsa_key_bits(const encrcdsa_info_t* info) {
	return info->key_bits;
}

void encrcdsa_key_hex(const encrcdsa_info_t* info, char* out) {
	int i, n = info->key_bits / 8;
	for(i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", info->aes_key[i]);
	for(i = 0; i < 20; i++)
		sprintf(out + 2 * (n + i), "%02x", info->hmac_key[i]);
}

/* Apple Encrypted Archives */

typedef struct {
	uint64_t off;                 /* of the encrypted data in the archive */
	uint32_t csize;               /* stored size */
	uint32_t dsize;               /* decrypted size, 0 for a missing segment */
	uint32_t cluster;
	uint32_t index;               /* within the cluster */
	uint8_t mac[32];
	uint8_t checksum[32];
} aea_seg_t;

typedef struct {
	AbstractFile* file;
	uint8_t main_key[32];
	uint64_t size;                /* of the decrypted data */
	uint32_t seg_size;
	uint8_t compression;
	uint8_t checksum;
	aea_seg_t* segs;              /* in the order of the data */
	size_t nsegs;
	uint64_t pos;
	size_t cached;                /* segment in buf */
	int have_cached;
	uint8_t* buf;
	uint8_t* cbuf;
	uint8_t cluster_key[32];
	uint32_t key_cluster;         /* the cluster of cluster_key */
	int have_key;
	void* scratch;
} aea_t;

int aea_probe(AbstractFile* f) {
	uint8_t m[4];
	return read_at(f, 0, m, 4) && !memcmp(m, "AEA1", 4);
}

/* HKDF-SHA256 with an empty salt of a label followed by an index */
static void aea_derive(const uint8_t key[32], const char* label, int indexed, uint32_t index, uint8_t* out, size_t len) {
	uint8_t info[16];
	size_t n = strlen(label);
	memcpy(info, label, n);
	if(indexed) {
		info[n++] = (uint8_t)index;
		info[n++] = (uint8_t)(index >> 8);
		info[n++] = (uint8_t)(index >> 16);
		info[n++] = (uint8_t)(index >> 24);
	}
	apfs_hkdf_sha256(key, 32, NULL, 0, info, n, out, len);
}

/* HMAC-SHA256 of a salt (in two pieces), the data and the salt's length */
static void aea_mac(const uint8_t key[32], const uint8_t* s1, size_t n1, const uint8_t* s2, size_t n2, const uint8_t* data, size_t len, uint8_t mac[32]) {
	apfs_hmac_sha256_ctx c;
	uint64_t sl = (uint64_t)n1 + n2;
	uint8_t l[8];
	int i;
	for(i = 0; i < 8; i++)
		l[i] = (uint8_t)(sl >> (8 * i));
	apfs_hmac_sha256_init(&c, key, 32);
	apfs_hmac_sha256_update(&c, s1, n1);
	apfs_hmac_sha256_update(&c, s2, n2);
	apfs_hmac_sha256_update(&c, data, len);
	apfs_hmac_sha256_update(&c, l, 8);
	apfs_hmac_sha256_final(&c, mac);
}

/* Material for a MAC key, an AES key and an IV */
#define AEA_MAC(m) (m)
#define AEA_KEY(m) ((m) + 32)
#define AEA_IV(m) ((m) + 64)

static void aea_ctr(const uint8_t* m, uint8_t* data, size_t len) {
	apfs_aes_ctx aes;
	apfs_aes_init(&aes, AEA_KEY(m), 32);
	apfs_aes_ctr(&aes, AEA_IV(m), data, data, len);
}

static int aea_load(aea_t* a, size_t g) {
	aea_seg_t* s = &a->segs[g];
	uint8_t sk[80], mac[32];

	if(!s->dsize)
		return APFS_ECORRUPT;
	if(!a->have_key || a->key_cluster != s->cluster) {
		aea_derive(a->main_key, "AEA_CK", 1, s->cluster, a->cluster_key, 32);
		a->key_cluster = s->cluster;
		a->have_key = 1;
	}
	aea_derive(a->cluster_key, "AEA_SK", 1, s->index, sk, sizeof(sk));
	if(!read_at(a->file, s->off, a->cbuf, s->csize))
		return APFS_EIO;
	aea_mac(AEA_MAC(sk), NULL, 0, NULL, 0, a->cbuf, s->csize, mac);
	if(memcmp(mac, s->mac, 32) != 0)
		return APFS_ECORRUPT;
	aea_ctr(sk, a->cbuf, s->csize);
	if(s->csize == s->dsize) {
		memcpy(a->buf, a->cbuf, s->dsize);
	} else if(a->compression == 'e') {
		if(lzfse_decode_buffer(a->buf, s->dsize, a->cbuf, s->csize, a->scratch) != s->dsize)
			return APFS_ECORRUPT;
	} else {
		uLongf n = s->dsize;
		if(uncompress(a->buf, &n, a->cbuf, s->csize) != Z_OK || n != s->dsize)
			return APFS_ECORRUPT;
	}
	if(a->checksum == 2) {
		apfs_sha256(a->buf, s->dsize, mac);
		if(memcmp(mac, s->checksum, 32) != 0)
			return APFS_ECORRUPT;
	}
	a->cached = g;
	a->have_cached = 1;
	return APFS_OK;
}

static size_t aea_read(AbstractFile* af, void* data, size_t len) {
	aea_t* a = (aea_t*)af->data;
	size_t done = 0;

	while(done < len && a->pos < a->size) {
		size_t g = (size_t)(a->pos / a->seg_size), off = (size_t)(a->pos % a->seg_size), take;
		if(!a->have_cached || a->cached != g) {
			int ret = aea_load(a, g);
			if(ret < 0) {
				APFS_ERR("cannot read segment %llu of the archive: %s", (unsigned long long)g, apfs_strerror(ret));
				break;
			}
		}
		take = a->segs[g].dsize > off ? a->segs[g].dsize - off : 0;
		if(!take)
			break;
		if(take > len - done)
			take = len - done;
		memcpy((uint8_t*)data + done, a->buf + off, take);
		done += take;
		a->pos += take;
	}
	return done;
}

static int aea_seek(AbstractFile* af, off_t off) {
	((aea_t*)af->data)->pos = (uint64_t)off;
	return 0;
}

static off_t aea_tell(AbstractFile* af) {
	return (off_t)((aea_t*)af->data)->pos;
}

static off_t aea_length(AbstractFile* af) {
	return (off_t)((aea_t*)af->data)->size;
}

static void aea_free(aea_t* a) {
	free(a->segs);
	free(a->buf);
	free(a->cbuf);
	free(a->scratch);
	free(a);
}

static void aea_close(AbstractFile* af) {
	aea_t* a = (aea_t*)af->data;
	a->file->close(a->file);
	aea_free(a);
	free(af);
}

AbstractFile* aea_open(AbstractFile* f, const uint8_t* key, size_t key_len) {
	uint8_t h[12], pre[144], info[11], rk[80], mac[32], root[48];
	uint8_t* auth = NULL;
	uint8_t* block = NULL;
	uint32_t profile, alen, per_cluster, cks, c;
	uint64_t off, total = 0, max_csize = 0;
	aea_t* a = (aea_t*)apfs_calloc(1, sizeof(aea_t));
	AbstractFile* af;
	const uint8_t* expect;
	uint8_t next[32];

	a->file = f;
	if(!read_at(f, 0, h, sizeof(h)) || memcmp(h, "AEA1", 4) != 0) {
		APFS_ERR("not an Apple Encrypted Archive");
		goto fail;
	}
	profile = le32(h + 4) & 0xffffff;
	alen = le32(h + 8);
	if(profile != 1) {
		APFS_ERR("AEA profile %u is not supported, only profile 1 (a symmetric key, no signature)", profile);
		goto fail;
	}
	if(!key) {
		APFS_ERR("the archive is encrypted: give its key with -k");
		goto fail;
	}
	if(key_len != 32) {
		APFS_ERR("the key of an archive has 32 bytes");
		goto fail;
	}
	if(alen > (16 << 20)) {
		APFS_ERR("damaged archive");
		goto fail;
	}
	auth = (uint8_t*)apfs_malloc(alen + 1);
	if(!read_at(f, 12, auth, alen) || !read_at(f, 12 + (uint64_t)alen, pre, sizeof(pre))) {
		APFS_ERR("damaged archive");
		goto fail;
	}
	/* the main key, then the root header: salt, MAC, 48 bytes, the MAC of
	 * the first cluster */
	memcpy(info, "AEA_AMK", 7);
	memcpy(info + 7, h + 4, 4);
	apfs_hkdf_sha256(key, 32, pre, 32, info, sizeof(info), a->main_key, 32);
	aea_derive(a->main_key, "AEA_RHEK", 0, 0, rk, sizeof(rk));
	aea_mac(AEA_MAC(rk), pre + 112, 32, auth, alen, pre + 64, 48, mac);
	if(memcmp(mac, pre + 32, 32) != 0) {
		APFS_ERR("the key does not match the archive");
		goto fail;
	}
	memcpy(root, pre + 64, 48);
	aea_ctr(rk, root, 48);
	a->size = le64(root);
	a->seg_size = le32(root + 16);
	per_cluster = le32(root + 20);
	a->compression = root[24];
	a->checksum = root[25];
	cks = a->checksum == 2 ? 32 : a->checksum == 1 ? 8 : 0;
	if(a->compression != '-' && a->compression != 'e' && a->compression != 'z') {
		APFS_ERR("the archive's compression ('%c') is not supported, only none, lzfse and zlib", a->compression);
		goto fail;
	}
	if(!a->seg_size || a->seg_size > (64 << 20) || !per_cluster || per_cluster > 65536 || a->checksum > 2) {
		APFS_ERR("damaged archive");
		goto fail;
	}
	a->nsegs = (size_t)((a->size + a->seg_size - 1) / a->seg_size);
	a->segs = (aea_seg_t*)apfs_calloc(a->nsegs + 1, sizeof(aea_seg_t));

	/* each cluster: encrypted segment headers, the MAC of the next cluster,
	 * the MACs of the segments, then their data */
	off = 12 + (uint64_t)alen + sizeof(pre);
	expect = pre + 112;
	block = (uint8_t*)apfs_malloc((size_t)per_cluster * (8 + cks + 32) + 32);
	for(c = 0; total < a->size; c++) {
		size_t hl = (size_t)per_cluster * (8 + cks), bl = hl + 32 + 32 * (size_t)per_cluster, s;
		uint8_t ck[32], chek[80];
		uint64_t data = off + bl, added = 0;
		if(!read_at(f, off, block, bl)) {
			APFS_ERR("damaged archive: cluster %u is missing", c);
			goto fail;
		}
		aea_derive(a->main_key, "AEA_CK", 1, c, ck, 32);
		aea_derive(ck, "AEA_CHEK", 0, 0, chek, sizeof(chek));
		aea_mac(AEA_MAC(chek), block + hl, bl - hl, NULL, 0, block, hl, mac);
		if(memcmp(mac, expect, 32) != 0) {
			APFS_ERR("damaged archive: cluster %u", c);
			goto fail;
		}
		memcpy(next, block + hl, 32);
		expect = next;
		aea_ctr(chek, block, hl);
		for(s = 0; s < per_cluster; s++) {
			const uint8_t* sh = block + s * (8 + cks);
			uint64_t g = (uint64_t)c * per_cluster + s;
			aea_seg_t* seg;
			if(!le32(sh))
				continue;
			if(g >= a->nsegs || le32(sh) > a->seg_size || (g + 1 < a->nsegs && le32(sh) != a->seg_size)) {
				APFS_ERR("damaged archive: segment %llu", (unsigned long long)g);
				goto fail;
			}
			seg = &a->segs[g];
			seg->off = data;
			seg->dsize = le32(sh);
			seg->csize = le32(sh + 4);
			seg->cluster = c;
			seg->index = (uint32_t)s;
			memcpy(seg->mac, block + hl + 32 + 32 * s, 32);
			memcpy(seg->checksum, sh + 8, cks);
			data += seg->csize;
			added += seg->dsize;
			if(seg->csize > max_csize)
				max_csize = seg->csize;
		}
		if(!added) {
			APFS_ERR("damaged archive: cluster %u is empty", c);
			goto fail;
		}
		total += added;
		off = data;
	}
	if(total != a->size || max_csize > (128 << 20)) {
		APFS_ERR("damaged archive");
		goto fail;
	}
	free(block);
	free(auth);
	a->buf = (uint8_t*)apfs_malloc(a->seg_size);
	a->cbuf = (uint8_t*)apfs_malloc((size_t)max_csize + 1);
	a->scratch = apfs_malloc(lzfse_decode_scratch_size() + 1);

	af = (AbstractFile*)apfs_calloc(1, sizeof(AbstractFile));
	af->data = a;
	af->read = aea_read;
	af->write = encrypted_write;
	af->seek = aea_seek;
	af->tell = aea_tell;
	af->getLength = aea_length;
	af->close = aea_close;
	af->type = AbstractFileTypeFile;
	return af;

fail:
	free(block);
	free(auth);
	aea_free(a);
	f->close(f);
	return NULL;
}
