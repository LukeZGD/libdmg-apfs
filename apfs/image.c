/*
 * image.c
 * apfs-tool
 *
 * Opens the files that hold APFS containers: raw images (bare or GPT
 * partitioned), UDIF disk images and IMG4 payloads. Disk images and IMG4
 * payloads are read in place; when they are opened for writing, a raw working
 * copy is modified and packed again in the original format on close.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"
#include "apfs/image.h"
#include "apfs/udif.h"
#include "apfs/encrypted.h"
#include "apfs/platform.h"
#include "lzfse.h"

/* APFS partition type 7C3457EF-0000-11AA-AA11-00306543ECAC, in GPT byte order */
static const uint8_t gpt_apfs_type[16] = {
	0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC
};

const char* apfs_image_tmpdir = NULL;
const char* apfs_image_key = NULL;
const char* apfs_image_passphrase = NULL;

static int has_nxsb(io_func* io, uint64_t off) {
	uint8_t buf[64];
	if(!io->read(io, (off_t)off, sizeof(buf), buf))
		return 0;
	return apfs_get32(buf + 32) == NX_MAGIC;
}

static int find_gpt(io_func* io, uint32_t ss, uint64_t* base, uint64_t* length) {
	uint8_t hdr[512];
	uint8_t* entries;
	uint64_t entries_lba;
	uint32_t count, esize, i;

	if(!io->read(io, (off_t)ss, sizeof(hdr), hdr))
		return 0;
	if(memcmp(hdr, "EFI PART", 8) != 0)
		return 0;
	entries_lba = apfs_get64(hdr + 72);
	count = apfs_get32(hdr + 80);
	esize = apfs_get32(hdr + 84);
	if(esize < 128 || esize > 4096 || count == 0 || count > 1024)
		return 0;
	entries = (uint8_t*)apfs_malloc((size_t)count * esize);
	if(!io->read(io, (off_t)(entries_lba * ss), (size_t)count * esize, entries)) {
		free(entries);
		return 0;
	}
	for(i = 0; i < count; i++) {
		uint8_t* e = entries + (size_t)i * esize;
		uint64_t first = apfs_get64(e + 32), last = apfs_get64(e + 40);
		if(memcmp(e, gpt_apfs_type, 16) == 0 && last >= first && has_nxsb(io, first * ss)) {
			*base = first * ss;
			*length = (last - first + 1) * ss;
			free(entries);
			return 1;
		}
	}
	for(i = 0; i < count; i++) {
		uint8_t* e = entries + (size_t)i * esize;
		uint64_t first = apfs_get64(e + 32), last = apfs_get64(e + 40);
		static const uint8_t zero[16] = { 0 };
		if(memcmp(e, zero, 16) != 0 && last >= first && has_nxsb(io, first * ss)) {
			*base = first * ss;
			*length = (last - first + 1) * ss;
			free(entries);
			return 1;
		}
	}
	free(entries);
	return 0;
}

int apfs_find_container(io_func* io, uint64_t dev_size, uint64_t* base, uint64_t* length) {
	*base = 0;
	*length = dev_size;
	if(has_nxsb(io, 0))
		return APFS_OK;
	if(find_gpt(io, 512, base, length) || find_gpt(io, 4096, base, length))
		return APFS_OK;
	return APFS_ENOENT;
}

/* IMG4 payloads */

typedef struct {
	char type[5];
	char* desc;
	int compressed;               /* payload was LZFSE compressed */
	uint8_t* img4_tail;           /* IM4M / IM4R of an IMG4 file, kept verbatim */
	size_t img4_tail_len;
	int is_img4;
} im4p_state_t;

static int der_len(const uint8_t* p, size_t avail, size_t* hdr, uint64_t* len) {
	if(avail < 2)
		return 0;
	if(p[1] < 0x80) {
		*hdr = 2;
		*len = p[1];
		return 1;
	} else {
		size_t n = p[1] & 0x7f, i;
		if(n == 0 || n > 8 || avail < 2 + n)
			return 0;
		*len = 0;
		for(i = 0; i < n; i++)
			*len = (*len << 8) | p[2 + i];
		*hdr = 2 + n;
		return 1;
	}
}

static int read_at(FILE* f, uint64_t off, void* buf, size_t len) {
	return fseeko(f, (off_t)off, SEEK_SET) == 0 && fread(buf, 1, len, f) == len;
}

/* Parses an IM4P (optionally inside IMG4); returns the payload location */
static int im4p_parse(FILE* f, uint64_t file_len, im4p_state_t* st, uint64_t* payload_off, uint64_t* payload_len) {
	uint8_t buf[512];
	size_t hdr, pos;
	uint64_t len, seq_end, start = 0;
	size_t n = file_len < sizeof(buf) ? (size_t)file_len : sizeof(buf);

	memset(st, 0, sizeof(*st));
	if(!read_at(f, 0, buf, n) || buf[0] != 0x30 || !der_len(buf, n, &hdr, &len))
		return 0;
	pos = hdr;
	if(pos + 6 <= n && buf[pos] == 0x16 && buf[pos + 1] == 4 && !memcmp(buf + pos + 2, "IMG4", 4)) {
		/* IMG4 { "IMG4", IM4P, [0] IM4M ... } */
		size_t h2;
		uint64_t l2;
		st->is_img4 = 1;
		pos += 6;
		if(pos >= n || buf[pos] != 0x30 || !der_len(buf + pos, n - pos, &h2, &l2))
			return 0;
		start = pos;
		{
			uint64_t im4p_end = start + h2 + l2;
			uint64_t outer_end = hdr + len;
			if(outer_end > file_len || im4p_end > outer_end)
				return 0;
			st->img4_tail_len = (size_t)(outer_end - im4p_end);
			if(st->img4_tail_len) {
				st->img4_tail = (uint8_t*)apfs_malloc(st->img4_tail_len);
				if(!read_at(f, im4p_end, st->img4_tail, st->img4_tail_len))
					return 0;
			}
		}
		if(!read_at(f, start, buf, n = (size_t)(file_len - start < sizeof(buf) ? file_len - start : sizeof(buf))))
			return 0;
		if(!der_len(buf, n, &hdr, &len))
			return 0;
		pos = hdr;
	}
	seq_end = start + hdr + len;
	if(pos + 6 > n || buf[pos] != 0x16 || buf[pos + 1] != 4 || memcmp(buf + pos + 2, "IM4P", 4) != 0)
		return 0;
	pos += 6;
	/* type */
	if(pos + 2 > n || buf[pos] != 0x16 || buf[pos + 1] != 4)
		return 0;
	memcpy(st->type, buf + pos + 2, 4);
	pos += 6;
	/* description */
	if(pos + 2 > n || buf[pos] != 0x16 || !der_len(buf + pos, n - pos, &hdr, &len) || pos + hdr + len > n)
		return 0;
	st->desc = (char*)apfs_malloc((size_t)len + 1);
	memcpy(st->desc, buf + pos + hdr, (size_t)len);
	st->desc[len] = 0;
	pos += hdr + (size_t)len;
	/* payload */
	if(pos + 2 > n || buf[pos] != 0x04 || !der_len(buf + pos, n - pos, &hdr, &len))
		return 0;
	*payload_off = start + pos + hdr;
	*payload_len = len;
	if(*payload_off + len > seq_end || seq_end > file_len)
		return 0;
	/* an optional compression info sequence follows the payload */
	{
		uint64_t after = *payload_off + len;
		uint8_t tail[64];
		size_t tn = (size_t)(seq_end - after < sizeof(tail) ? seq_end - after : sizeof(tail));
		if(tn && read_at(f, after, tail, tn)) {
			size_t p = 0;
			while(p + 2 <= tn) {
				size_t h3;
				uint64_t l3;
				if(!der_len(tail + p, tn - p, &h3, &l3))
					break;
				if(tail[p] == 0x30)
					st->compressed = 1;
				p += h3 + (size_t)l3;
			}
		}
	}
	{
		uint8_t magic[4];
		if(read_at(f, *payload_off, magic, 4) && (!memcmp(magic, "bvx2", 4) || !memcmp(magic, "bvx1", 4) || !memcmp(magic, "bvxn", 4) || !memcmp(magic, "bvx-", 4)))
			st->compressed = 1;
	}
	return 1;
}

static size_t der_put_len(uint8_t* p, uint64_t len) {
	if(len < 0x80) {
		p[0] = (uint8_t)len;
		return 1;
	} else {
		int n = 0, i;
		uint64_t t = len;
		while(t) {
			n++;
			t >>= 8;
		}
		p[0] = (uint8_t)(0x80 | n);
		for(i = 0; i < n; i++)
			p[1 + i] = (uint8_t)(len >> (8 * (n - 1 - i)));
		return (size_t)n + 1;
	}
}

static int copy_range(FILE* in, uint64_t off, uint64_t len, FILE* out) {
	uint8_t* buf = (uint8_t*)apfs_malloc(1 << 20);
	int ok = fseeko(in, (off_t)off, SEEK_SET) == 0;
	while(ok && len) {
		size_t n = len > (1 << 20) ? (1 << 20) : (size_t)len;
		ok = fread(buf, 1, n, in) == n && fwrite(buf, 1, n, out) == n;
		len -= n;
	}
	free(buf);
	return ok;
}

static size_t der_int(uint8_t* p, uint64_t v) {
	uint8_t tmp[9];
	int n = 0, i;
	do {
		tmp[8 - n] = (uint8_t)v;
		v >>= 8;
		n++;
	} while(v);
	if(tmp[9 - n] & 0x80)
		tmp[8 - n++] = 0;
	p[0] = 0x02;
	p[1] = (uint8_t)n;
	for(i = 0; i < n; i++)
		p[2 + i] = tmp[9 - n + i];
	return (size_t)n + 2;
}

/* The IM4P header up to the payload bytes: SEQUENCE { "IM4P", type,
 * description, OCTET STRING payload } followed by tail_len more bytes */
#define IM4P_HEADER_MAX 528

static size_t im4p_header(uint8_t* p, const char* type, const char* desc, uint64_t payload_len, uint64_t tail_len) {
	uint8_t inner[512];
	size_t ilen = 0, n = 0, dlen = desc ? strlen(desc) : 0;

	inner[ilen++] = 0x16; inner[ilen++] = 4; memcpy(inner + ilen, "IM4P", 4); ilen += 4;
	inner[ilen++] = 0x16; inner[ilen++] = 4; memcpy(inner + ilen, type, 4); ilen += 4;
	inner[ilen++] = 0x16; ilen += der_put_len(inner + ilen, dlen);
	if(dlen)
		memcpy(inner + ilen, desc, dlen);
	ilen += dlen;
	inner[ilen++] = 0x04; ilen += der_put_len(inner + ilen, payload_len);
	p[n++] = 0x30;
	n += der_put_len(p + n, ilen + payload_len + tail_len);
	memcpy(p + n, inner, ilen);
	return n + ilen;
}

/* Writes an IM4P (or IMG4) wrapping the contents of the raw working file */
/* The reference encoder slows down badly on long inputs full of zeros, so
 * large payloads are encoded in pieces. LZFSE blocks only refer back to data
 * of their own piece, so dropping each piece's end-of-stream marker except
 * the last joins them into one valid stream. */
#define LZFSE_PIECE (8U << 20)

static size_t lzfse_encode_chunked(uint8_t* dst, size_t cap, const uint8_t* src, size_t len, void* scratch) {
	size_t off = 0, out = 0;
	do {
		size_t piece = len - off < LZFSE_PIECE ? len - off : LZFSE_PIECE;
		size_t n = lzfse_encode_buffer(dst + out, cap - out, src + off, piece, scratch);
		if(n < 4 || memcmp(dst + out + n - 4, "bvx$", 4) != 0)
			return 0;
		off += piece;
		out += off < len ? n - 4 : n;
	} while(off < len);
	return out;
}

static int im4p_write(const im4p_state_t* st, const char* raw_path, uint64_t raw_len, const char* out_path) {
	FILE* in = fopen(raw_path, "rb");
	FILE* out;
	uint8_t head[IM4P_HEADER_MAX], comp[32], outer[32];
	size_t hlen, clen = 0, olen = 0;
	size_t dlen = st->desc ? strlen(st->desc) : 0;
	uint64_t payload_len = raw_len;
	uint8_t* compressed = NULL;
	int ok;

	if(!in || dlen > 400) {
		if(in)
			fclose(in);
		return APFS_EIO;
	}
	if(st->compressed) {
		uint8_t* data = (uint8_t*)apfs_malloc((size_t)raw_len + 1);
		size_t cap = (size_t)raw_len + 65536;
		void* scratch;
		if(!read_at(in, 0, data, (size_t)raw_len)) {
			free(data);
			fclose(in);
			return APFS_EIO;
		}
		compressed = (uint8_t*)apfs_malloc(cap);
		scratch = apfs_malloc(lzfse_encode_scratch_size() + 1);
		payload_len = lzfse_encode_chunked(compressed, cap, data, (size_t)raw_len, scratch);
		free(scratch);
		free(data);
		if(!payload_len) {
			free(compressed);
			fclose(in);
			return APFS_EIO;
		}
		/* compression info: SEQUENCE { INTEGER 1 (LZFSE), INTEGER uncompressed size } */
		{
			uint8_t seq[24];
			size_t sl = der_int(seq, 1);
			sl += der_int(seq + sl, raw_len);
			comp[clen++] = 0x30;
			clen += der_put_len(comp + clen, sl);
			memcpy(comp + clen, seq, sl);
			clen += sl;
		}
	}

	hlen = im4p_header(head, st->type, st->desc, payload_len, clen);
	if(st->is_img4) {
		uint64_t outer_len = 6 + hlen + payload_len + clen + st->img4_tail_len;
		outer[olen++] = 0x30;
		olen += der_put_len(outer + olen, outer_len);
		memcpy(outer + olen, "\x16\x04IMG4", 6);
		olen += 6;
	}

	out = fopen(out_path, "wb");
	if(!out) {
		free(compressed);
		fclose(in);
		return APFS_EIO;
	}
	ok = fwrite(outer, 1, olen, out) == olen && fwrite(head, 1, hlen, out) == hlen;
	if(ok)
		ok = compressed ? fwrite(compressed, 1, (size_t)payload_len, out) == payload_len : copy_range(in, 0, raw_len, out);
	if(ok && clen)
		ok = fwrite(comp, 1, clen, out) == clen;
	if(ok && st->is_img4 && st->img4_tail_len)
		ok = fwrite(st->img4_tail, 1, st->img4_tail_len, out) == st->img4_tail_len;
	if(fclose(out) != 0)
		ok = 0;
	fclose(in);
	free(compressed);
	return ok ? APFS_OK : APFS_EIO;
}

/* Small payloads held in memory, such as trust caches */

int apfs_im4p_load(const char* path, uint8_t** data, size_t* len) {
	FILE* f = fopen(path, "rb");
	im4p_state_t st;
	uint64_t flen, off = 0, plen;
	int ret = APFS_OK;

	if(!f)
		return APFS_EIO;
	memset(&st, 0, sizeof(st));
	fseeko(f, 0, SEEK_END);
	flen = (uint64_t)ftello(f);
	if(flen && im4p_parse(f, flen, &st, &off, &plen)) {
		if(st.compressed)
			ret = APFS_EUNSUPP;
	} else {
		off = 0;
		plen = flen;
	}
	free(st.desc);
	free(st.img4_tail);
	if(ret == APFS_OK) {
		*data = (uint8_t*)apfs_malloc((size_t)plen);
		*len = (size_t)plen;
		if(!read_at(f, off, *data, *len)) {
			free(*data);
			ret = APFS_EIO;
		}
	}
	fclose(f);
	return ret;
}

int apfs_im4p_save(const char* type, const char* desc, const void* data, size_t len, const char* path) {
	uint8_t head[IM4P_HEADER_MAX];
	size_t hlen;
	FILE* f;
	int ok;

	if(strlen(type) != 4 || (desc && strlen(desc) > 400))
		return APFS_EINVAL;
	hlen = im4p_header(head, type, desc, len, 0);
	f = fopen(path, "wb");
	if(!f)
		return APFS_EIO;
	ok = fwrite(head, 1, hlen, f) == hlen && fwrite(data, 1, len, f) == len;
	if(fclose(f) != 0)
		ok = 0;
	return ok ? APFS_OK : APFS_EIO;
}

/* Images */

typedef struct {
	uint32_t compression;
	int imagescan;
	im4p_state_t im4p;
	uint64_t raw_len;
	encrcdsa_info_t* encr;        /* how to encrypt an encrypted image again */
} pack_state_t;

static char* work_path_for(const char* path) {
	const char* base = strrchr(path, '/');
	char* hint;
	char* r;
	base = base ? base + 1 : path;
	hint = (char*)apfs_malloc(strlen(base) + 8);
	sprintf(hint, "%s.raw", base);
	if(apfs_image_tmpdir) {
		char name[300];
		uint8_t u[16];
		apfs_uuid_generate(u);
		snprintf(name, sizeof(name), "apfs-tool-%02x%02x%02x%02x-%s", u[0], u[1], u[2], u[3], hint);
		r = plat_join(apfs_image_tmpdir, name);
	} else {
		r = plat_temp_path(hint);
	}
	free(hint);
	return r;
}

static int open_container(apfs_image_t* img, uint64_t dev_size) {
	int ret = apfs_find_container(img->io, dev_size, &img->base, &img->length);
	if(ret < 0) {
		APFS_ERR("%s does not contain an APFS container", img->path);
		return APFS_EINVAL;
	}
	ret = apfs_nx_open(&img->nx, img->io, img->base, img->writable);
	if(ret < 0)
		APFS_ERR("cannot open the APFS container: %s", apfs_strerror(ret));
	return ret;
}

static void image_free(apfs_image_t* img) {
	pack_state_t* ps = (pack_state_t*)img->format_state;
	if(img->io)
		CLOSE(img->io);
	if(img->work_path) {
		plat_remove(img->work_path);
		free(img->work_path);
	}
	if(ps) {
		free(ps->im4p.desc);
		free(ps->im4p.img4_tail);
		encrcdsa_info_free(ps->encr);
		free(ps);
	}
	free(img->out_path);
	free(img->path);
	free(img);
}

static int export_raw(io_func* io, uint64_t off, uint64_t len, const char* path);

/* Copies a raw image the way it is exported, so the copy stays sparse */
static int copy_file(const char* src, const char* dst) {
	io_func* io = apfs_rawfile_open(src, 0);
	int ret;
	if(!io)
		return APFS_EIO;
	ret = export_raw(io, 0, apfs_rawfile_size(io), dst);
	CLOSE(io);
	return ret;
}

static pack_state_t* pack_state(apfs_image_t* img) {
	if(!img->format_state)
		img->format_state = apfs_calloc(1, sizeof(pack_state_t));
	return (pack_state_t*)img->format_state;
}

/* A UDIF disk image in af, which this takes over */
static int open_udif(apfs_image_t* img, AbstractFile* af) {
	udif_t* u = udif_open(af);
	pack_state_t* ps;
	FILE* w;
	int ret;

	if(!u) {
		APFS_ERR("%s is not a supported disk image", img->path);
		af->close(af);
		return APFS_EINVAL;
	}
	img->format = APFS_IMG_DMG;
	ps = pack_state(img);
	ps->compression = udif_main_compression(u);
	ps->imagescan = 1;
	if(!img->writable) {
		img->io = udif_io(u);
		return open_container(img, udif_sectors(u) * UDIF_SECTOR);
	}
	img->work_path = work_path_for(img->path);
	w = fopen(img->work_path, "w+b");
	if(!w) {
		APFS_ERR("cannot create working file %s", img->work_path);
		udif_close(u);
		return APFS_EIO;
	}
	ret = udif_extract(u, -1, w, apfs_verbosity < 2);
	fclose(w);
	ps->raw_len = udif_sectors(u) * UDIF_SECTOR;
	udif_close(u);
	if(ret < 0)
		return ret;
	img->io = apfs_rawfile_open(img->work_path, 1);
	return img->io ? open_container(img, ps->raw_len) : APFS_EIO;
}

/* An encrypted image or archive in af, which this takes over: the disk
 * image it holds is read through a view that decrypts it */
static int open_encrypted(apfs_image_t* img, AbstractFile* af) {
	int aea = aea_probe(af);
	uint8_t* key = NULL;
	size_t klen = 0;
	AbstractFile* view;
	io_func* io;
	const char* dst;
	uint64_t len;
	int ret;

	if(apfs_image_key && apfs_parse_key(apfs_image_key, &key, &klen) < 0) {
		APFS_ERR("invalid key: give it as hex digits or base64");
		af->close(af);
		return APFS_EINVAL;
	}
	if(aea && img->writable && plat_same_file(img->out_path, img->path)) {
		APFS_ERR("%s is an encrypted archive, which apfs-tool cannot write; save the changes elsewhere with -o", img->path);
		free(key);
		af->close(af);
		return APFS_EROFS;
	}
	view = aea ? aea_open(af, key, klen) :
		encrcdsa_open(af, key, klen, apfs_image_passphrase, img->writable ? &pack_state(img)->encr : NULL);
	free(key);
	if(!view)
		return APFS_EINVAL;
	if(udif_probe(view))
		return open_udif(img, view);

	/* a raw disk, read through the view or written in a decrypted copy:
	 * the one of an archive goes to -o, the one of an encrypted image is
	 * encrypted again on close */
	img->format = APFS_IMG_RAW;
	len = (uint64_t)view->getLength(view);
	io = IOFuncFromAbstractFile(view);
	if(!img->writable) {
		img->io = io;
		return open_container(img, len);
	}
	if(!aea)
		img->work_path = work_path_for(img->path);
	dst = aea ? img->out_path : img->work_path;
	ret = export_raw(io, 0, len, dst);
	CLOSE(io);
	if(ret < 0)
		return ret;
	img->io = apfs_rawfile_open(dst, 1);
	return img->io ? open_container(img, len) : APFS_EIO;
}

int apfs_image_open_ex(const char* path, int writable, const char* out_path, apfs_image_t** out) {
	apfs_image_t* img;
	AbstractFile* af;
	FILE* f;
	uint64_t flen;
	int ret;

	img = (apfs_image_t*)apfs_calloc(1, sizeof(apfs_image_t));
	img->path = apfs_strdup(path);
	img->writable = writable;
	img->out_path = apfs_strdup(out_path ? out_path : path);
	/* An alias of the input means "edit in place" too.  Repackers replace
	 * their output with a temporary file, so keeping a symlink or hard-link
	 * spelling here would replace that directory entry instead of the input. */
	if(writable && out_path && plat_same_file(path, out_path)) {
		free(img->out_path);
		img->out_path = apfs_strdup(path);
	}

	f = fopen(path, "rb");
	if(!f) {
		APFS_ERR("cannot open %s", path);
		image_free(img);
		return APFS_EIO;
	}
	fseeko(f, 0, SEEK_END);
	flen = (uint64_t)ftello(f);

	/* encrypted image or archive, or UDIF disk image? */
	af = createAbstractFileFromFile(f);
	if(encrcdsa_probe(af) || aea_probe(af) || udif_probe(af)) {
		ret = encrcdsa_probe(af) || aea_probe(af) ? open_encrypted(img, af) : open_udif(img, af);
		if(ret < 0) {
			image_free(img);
			return ret;
		}
		*out = img;
		return APFS_OK;
	}
	/* keep using f below; the AbstractFile wrapper only owns it when used */
	free(af);

	/* IMG4 payload? */
	{
		im4p_state_t st;
		uint64_t poff, plen;
		uint8_t magic[2];
		if(read_at(f, 0, magic, 2) && magic[0] == 0x30 && im4p_parse(f, flen, &st, &poff, &plen)) {
			pack_state_t* ps = (pack_state_t*)apfs_calloc(1, sizeof(pack_state_t));
			FILE* w;
			img->format = APFS_IMG_IM4P;
			ps->im4p = st;
			img->format_state = ps;
			img->work_path = work_path_for(path);
			w = fopen(img->work_path, "w+b");
			if(!w) {
				fclose(f);
				image_free(img);
				return APFS_EIO;
			}
			if(st.compressed) {
				uint8_t* in = (uint8_t*)apfs_malloc((size_t)plen + 1);
				size_t cap = (size_t)plen * 8 + (1 << 20), got;
				uint8_t* outb = NULL;
				void* scratch = apfs_malloc(lzfse_decode_scratch_size() + 1);
				ret = read_at(f, poff, in, (size_t)plen) ? APFS_OK : APFS_EIO;
				for(; ret == APFS_OK; cap *= 2) {
					outb = (uint8_t*)apfs_realloc(outb, cap);
					got = lzfse_decode_buffer(outb, cap, in, (size_t)plen, scratch);
					if(got < cap) {
						ps->raw_len = got;
						ret = fwrite(outb, 1, got, w) == got ? APFS_OK : APFS_EIO;
						break;
					}
				}
				free(scratch);
				free(outb);
				free(in);
			} else {
				ps->raw_len = plen;
				ret = copy_range(f, poff, plen, w) ? APFS_OK : APFS_EIO;
			}
			fclose(w);
			fclose(f);
			if(ret == APFS_OK) {
				img->io = apfs_rawfile_open(img->work_path, writable);
				ret = img->io ? open_container(img, ps->raw_len) : APFS_EIO;
			}
			if(ret < 0) {
				image_free(img);
				return ret;
			}
			*out = img;
			return APFS_OK;
		}
	}
	fclose(f);

	/* raw image */
	img->format = APFS_IMG_RAW;
	/* -o naming the image itself, by whatever path, edits it in place:
	 * copying a file onto itself would empty it */
	if(writable && out_path && !plat_same_file(path, out_path)) {
		ret = copy_file(path, out_path);
		if(ret < 0) {
			APFS_ERR("cannot copy %s to %s", path, out_path);
			image_free(img);
			return ret;
		}
		img->io = apfs_rawfile_open(out_path, 1);
	} else {
		img->io = apfs_rawfile_open(path, writable);
	}
	if(!img->io) {
		APFS_ERR("cannot open %s", path);
		image_free(img);
		return APFS_EIO;
	}
	ret = open_container(img, apfs_rawfile_size(img->io));
	if(ret < 0) {
		image_free(img);
		return ret;
	}
	*out = img;
	return APFS_OK;
}

int apfs_image_open(const char* path, int writable, apfs_image_t** out) {
	return apfs_image_open_ex(path, writable, NULL, out);
}

typedef struct {
	apfs_sm_t* sm;
	uint32_t bs;
} free_ctx_t;

static int block_range_free(void* ctx, uint64_t off, uint64_t len) {
	free_ctx_t* c = (free_ctx_t*)ctx;
	uint64_t b = off / c->bs, e = (off + len + c->bs - 1) / c->bs, i;
	for(i = b; i < e; i++) {
		if(i >= c->sm->nblocks)
			return 1; /* past the container */
		if((c->sm->bitmap[i >> 3] >> (i & 7)) & 1)
			return 0;
	}
	return 1;
}

/* Encrypts a plain file to the output, with the header (and so the keys
 * and the passphrase) of the encrypted image it came from */
static int save_encrypted(apfs_image_t* img, const char* plain, uint64_t len) {
	pack_state_t* ps = (pack_state_t*)img->format_state;
	char* tmp = (char*)apfs_malloc(strlen(img->out_path) + 16);
	FILE* in = fopen(plain, "rb");
	FILE* out = NULL;
	int ret = APFS_EIO;

	sprintf(tmp, "%s.apfs-tool", img->out_path);
	if(in && (out = fopen(tmp, "wb")) != NULL) {
		ret = encrcdsa_save(ps->encr, in, len, out);
		if(fclose(out) != 0 && ret == APFS_OK)
			ret = APFS_EIO;
		if(ret == APFS_OK) {
			remove(img->out_path);
			if(rename(tmp, img->out_path) != 0)
				ret = APFS_EIO;
		}
		if(ret < 0)
			remove(tmp);
	}
	if(in)
		fclose(in);
	free(tmp);
	return ret;
}

/* Packs the working copy of a DMG; an encrypted one is packed to a plain
 * file first */
static int repack_dmg(apfs_image_t* img) {
	pack_state_t* ps = (pack_state_t*)img->format_state;
	udif_build_opts_t o;
	free_ctx_t fc;
	char* tmp;
	FILE* out;
	uint64_t size;
	const char* names[NX_MAX_FILE_SYSTEMS];
	const char* uuids[NX_MAX_FILE_SYSTEMS];
	char uuidbuf[NX_MAX_FILE_SYSTEMS][37];
	uint64_t disk_bytes = apfs_rawfile_size(img->io);
	int i, ret;

	udif_default_opts(&o);
	o.compression = ps->compression;
	if(o.compression != UDIF_ZLIB && o.compression != UDIF_LZFSE && o.compression != UDIF_RAW
#ifdef HAVE_BZIP2
			&& o.compression != UDIF_BZIP2
#endif
#ifdef HAVE_LZMA
			&& o.compression != UDIF_LZMA
#endif
			)
		o.compression = UDIF_ZLIB;
	o.imagescan = ps->imagescan;
	o.quiet = apfs_verbosity < 2;
	if(apfs_sm_load(img->nx) == APFS_OK) {
		fc.sm = &img->nx->sm;
		fc.bs = img->nx->bs;
		o.is_free = block_range_free;
		o.free_ctx = &fc;
	}
	for(i = 0; i < NX_MAX_FILE_SYSTEMS; i++) {
		apfs_vol_t* v;
		if(!img->nx->sb->nx_fs_oid[i] || apfs_vol_open(img->nx, i, &v) < 0)
			continue;
		names[o.nvolumes] = (const char*)v->sb->apfs_volname;
		apfs_uuid_format(v->sb->apfs_vol_uuid, uuidbuf[o.nvolumes]);
		uuids[o.nvolumes] = uuidbuf[o.nvolumes];
		o.nvolumes++;
	}
	o.volume_names = names;
	o.volume_uuids = uuids;

	tmp = (char*)apfs_malloc(strlen(ps->encr ? img->work_path : img->out_path) + 16);
	sprintf(tmp, "%s.%s", ps->encr ? img->work_path : img->out_path, ps->encr ? "dmg" : "apfs-tool");
	out = fopen(tmp, "wb");
	if(!out) {
		free(tmp);
		return APFS_EIO;
	}
	if(apfs_verbosity >= 1)
		printf("Packing %s (%s)...\n", img->out_path, udif_format_name(o.compression));
	ret = udif_build(img->io, disk_bytes, out, &o);
	size = (uint64_t)ftello(out);
	if(fclose(out) != 0 && ret == APFS_OK)
		ret = APFS_EIO;
	if(ret == APFS_OK && ps->encr) {
		ret = save_encrypted(img, tmp, size);
		remove(tmp);
	} else if(ret == APFS_OK) {
		remove(img->out_path);
		if(rename(tmp, img->out_path) != 0)
			ret = APFS_EIO;
	}
	if(ret < 0)
		remove(tmp);
	free(tmp);
	return ret;
}

int apfs_image_close(apfs_image_t* img, int save) {
	int ret = APFS_OK;
	if(!img)
		return APFS_OK;
	if(img->nx) {
		int modified = img->nx->txn != 0 || img->dirty;
		if(!save)
			img->nx->txn = 0;
		else if(img->nx->txn)
			ret = apfs_nx_commit(img->nx);
		if(ret == APFS_OK && save && modified && img->writable) {
			if(img->format == APFS_IMG_DMG) {
				ret = repack_dmg(img);
			} else if(img->format == APFS_IMG_IM4P) {
				pack_state_t* ps = (pack_state_t*)img->format_state;
				char* tmp = (char*)apfs_malloc(strlen(img->out_path) + 16);
				sprintf(tmp, "%s.apfs-tool", img->out_path);
				ret = im4p_write(&ps->im4p, img->work_path, apfs_rawfile_size(img->io), tmp);
				if(ret == APFS_OK) {
					remove(img->out_path);
					if(rename(tmp, img->out_path) != 0)
						ret = APFS_EIO;
				}
				if(ret < 0)
					remove(tmp);
				free(tmp);
			} else if(img->format_state && ((pack_state_t*)img->format_state)->encr) {
				/* a raw disk in an encrypted image */
				ret = apfs_rawfile_flush(img->io);
				if(ret == APFS_OK)
					ret = save_encrypted(img, img->work_path, apfs_rawfile_size(img->io));
			}
		}
		apfs_nx_close(img->nx);
		img->nx = NULL;
	}
	image_free(img);
	return ret;
}

io_func* apfs_subrange_io(io_func* inner, uint64_t off, uint64_t len);

int apfs_image_range_free(void* ctx, uint64_t off, uint64_t len) {
	return block_range_free(ctx, off, len);
}

/* Grows the container, and the file or partition that holds it */
int apfs_image_grow(apfs_image_t* img, uint64_t new_size) {
	apfs_nx_t* nx = img->nx;
	uint64_t old_size = LE64(nx->sb->nx_block_count) * nx->bs;
	int ret;

	new_size = new_size / nx->bs * nx->bs;
	if(new_size < old_size) {
		APFS_ERR("cannot shrink the container (%llu < %llu bytes)", (unsigned long long)new_size, (unsigned long long)old_size);
		return APFS_EUNSUPP;
	}
	if(new_size == old_size)
		return APFS_OK;
	if(img->base == 0) {
		ret = apfs_rawfile_truncate(img->io, new_size);
	} else {
		uint64_t old_disk = apfs_rawfile_size(img->io);
		uint64_t new_disk = img->base + new_size + 33 * 512;
		uint64_t off, len;
		int idx;
		ret = udif_gpt_find(img->io, old_disk, &off, &len, &idx);
		if(ret == APFS_OK && off != img->base)
			ret = APFS_EINVAL;
		if(ret == APFS_OK)
			ret = apfs_rawfile_truncate(img->io, new_disk);
		if(ret == APFS_OK)
			ret = udif_gpt_resize(img->io, old_disk, new_disk, idx, new_size);
		if(ret == APFS_OK)
			img->length = new_size;
	}
	if(ret < 0)
		return ret;
	ret = apfs_nx_resize(nx, new_size);
	if(ret == APFS_OK)
		img->dirty = 1;
	return ret;
}

/* Runs of zeros are skipped, so the output is sparse where the host file
 * system allows it: free space in large images costs no disk space */
static int export_raw(io_func* io, uint64_t off, uint64_t len, const char* path) {
	FILE* f = fopen(path, "w+b");
	uint8_t* buf;
	uint64_t pos = 0;
	int ret = APFS_OK;
	if(!f)
		return APFS_EIO;
	if(plat_sparse_file(f, len) < 0) {
		fclose(f);
		return APFS_EIO;
	}
	buf = (uint8_t*)apfs_malloc(1 << 20);
	while(pos < len && ret == APFS_OK) {
		size_t n = len - pos > (1 << 20) ? (1 << 20) : (size_t)(len - pos);
		if(!io->read(io, (off_t)(off + pos), n, buf)) {
			ret = APFS_EIO;
			break;
		}
		ret = plat_write_sparse(f, pos, buf, n);
		pos += n;
	}
	free(buf);
	if(ret == APFS_OK)
		ret = plat_sparse_finish(f);
	if(fclose(f) != 0 && ret == APFS_OK)
		ret = APFS_EIO;
	return ret;
}

static uint64_t disk_bytes_of(apfs_image_t* img) {
	uint64_t container = LE64(img->nx->sb->nx_block_count) * img->nx->bs;
	if(img->base == 0)
		return container;
	/* partitioned: through the backup GPT */
	return img->base + (img->length ? img->length : container) + 33 * 512;
}

int apfs_image_export(apfs_image_t* img, const char* fmt, const char* out_path, int argc, char** argv) {
	apfs_nx_t* nx = img->nx;
	uint64_t container = LE64(nx->sb->nx_block_count) * nx->bs;
	int i, ret = APFS_OK;

	/* writing the image while reading it would destroy it */
	if(plat_same_file(out_path, img->path)) {
		APFS_ERR("%s is the image itself", out_path);
		return APFS_EINVAL;
	}

	if(!strcmp(fmt, "raw")) {
		int only_container = argc > 0 && !strcmp(argv[0], "-c");
		if(only_container || img->base == 0)
			return export_raw(img->io, img->base, container, out_path);
		return export_raw(img->io, 0, disk_bytes_of(img), out_path);
	}

	if(!strcmp(fmt, "im4p")) {
		pack_state_t* ps = img->format == APFS_IMG_IM4P ? (pack_state_t*)img->format_state : NULL;
		im4p_state_t st;
		char* tmp = plat_temp_path("im4p.raw");
		memset(&st, 0, sizeof(st));
		memcpy(st.type, ps ? ps->im4p.type : "rdsk", 4);
		st.desc = apfs_strdup(ps && ps->im4p.desc ? ps->im4p.desc : "0");
		for(i = 0; i < argc; i++) {
			if(!strcmp(argv[i], "-t") && i + 1 < argc) {
				size_t l = strlen(argv[++i]);
				memset(st.type, ' ', 4);
				memcpy(st.type, argv[i], l > 4 ? 4 : l);
			} else if(!strcmp(argv[i], "-d") && i + 1 < argc) {
				free(st.desc);
				st.desc = apfs_strdup(argv[++i]);
			} else if(!strcmp(argv[i], "-z")) {
				st.compressed = 1;
			} else {
				APFS_ERR("unknown option %s", argv[i]);
				free(st.desc);
				free(tmp);
				return APFS_EINVAL;
			}
		}
		ret = export_raw(img->io, img->base, container, tmp);
		if(ret == APFS_OK)
			ret = im4p_write(&st, tmp, container, out_path);
		plat_remove(tmp);
		free(tmp);
		free(st.desc);
		return ret;
	}

	if(!strcmp(fmt, "dmg")) {
		udif_build_opts_t o;
		io_func* disk = img->io;
		uint64_t bytes;
		int wrap = 1;
		FILE* f;
		free_ctx_t fc;
		const char* names[NX_MAX_FILE_SYSTEMS];
		const char* uuids[NX_MAX_FILE_SYSTEMS];
		char ubuf[NX_MAX_FILE_SYSTEMS][37];

		udif_default_opts(&o);
		o.compression = UDIF_LZFSE;
		for(i = 0; i < argc; i++) {
			if(!strcmp(argv[i], "-c") && i + 1 < argc) {
				i++;
				if(!strcmp(argv[i], "zlib")) o.compression = UDIF_ZLIB;
				else if(!strcmp(argv[i], "lzfse")) o.compression = UDIF_LZFSE;
				else if(!strcmp(argv[i], "raw")) o.compression = UDIF_RAW;
#ifdef HAVE_BZIP2
				else if(!strcmp(argv[i], "bzip2")) o.compression = UDIF_BZIP2;
#endif
#ifdef HAVE_LZMA
				else if(!strcmp(argv[i], "lzma")) o.compression = UDIF_LZMA;
#endif
				else {
					APFS_ERR("unknown compression %s", argv[i]);
					return APFS_EINVAL;
				}
			} else if(!strcmp(argv[i], "-b")) {
				wrap = 0;
			} else if(!strcmp(argv[i], "-n")) {
				o.imagescan = 0;
			} else {
				APFS_ERR("unknown option %s", argv[i]);
				return APFS_EINVAL;
			}
		}
		if(img->base == 0 && wrap) {
			disk = udif_gpt_wrap(img->io, container, &bytes);
		} else if(img->base != 0 && !wrap) {
			/* strip the partition map: export the container alone */
			bytes = container;
			disk = NULL;
		} else {
			bytes = disk_bytes_of(img);
		}
		if(apfs_sm_load(nx) == APFS_OK) {
			fc.sm = &nx->sm;
			fc.bs = nx->bs;
			o.is_free = block_range_free;
			o.free_ctx = &fc;
		}
		for(i = 0; i < NX_MAX_FILE_SYSTEMS; i++) {
			apfs_vol_t* v;
			if(!nx->sb->nx_fs_oid[i] || apfs_vol_open(nx, i, &v) < 0)
				continue;
			names[o.nvolumes] = (const char*)v->sb->apfs_volname;
			apfs_uuid_format(v->sb->apfs_vol_uuid, ubuf[o.nvolumes]);
			uuids[o.nvolumes] = ubuf[o.nvolumes];
			o.nvolumes++;
		}
		o.volume_names = names;
		o.volume_uuids = uuids;
		o.quiet = apfs_verbosity < 2;
		f = fopen(out_path, "wb");
		if(!f) {
			if(disk && disk != img->io)
				CLOSE(disk);
			return APFS_EIO;
		}
		if(!disk) {
			/* a view of the container without the partition map */
			io_func* sub = apfs_subrange_io(img->io, img->base, container);
			ret = udif_build(sub, bytes, f, &o);
			CLOSE(sub);
		} else {
			ret = udif_build(disk, bytes, f, &o);
		}
		if(fclose(f) != 0 && ret == APFS_OK)
			ret = APFS_EIO;
		if(disk && disk != img->io)
			CLOSE(disk);
		return ret;
	}
	APFS_ERR("unknown format %s", fmt);
	return APFS_EINVAL;
}

/* A read-only window into another io_func */
typedef struct {
	io_func* inner;
	uint64_t off;
	uint64_t len;
} subrange_t;

static int sub_read(io_func* io, off_t location, size_t size, void* buffer) {
	subrange_t* s = (subrange_t*)io->data;
	if((uint64_t)location + size > s->len) {
		size_t avail = (uint64_t)location < s->len ? (size_t)(s->len - (uint64_t)location) : 0;
		memset((uint8_t*)buffer + avail, 0, size - avail);
		size = avail;
		if(!size)
			return TRUE;
	}
	return s->inner->read(s->inner, (off_t)(s->off + (uint64_t)location), size, buffer);
}

static int sub_write(io_func* io, off_t location, size_t size, void* buffer) {
	subrange_t* s = (subrange_t*)io->data;
	if((uint64_t)location + size > s->len)
		return FALSE;
	return s->inner->write(s->inner, (off_t)(s->off + (uint64_t)location), size, buffer);
}

static void sub_close(io_func* io) {
	free(io->data);
	free(io);
}

io_func* apfs_subrange_io(io_func* inner, uint64_t off, uint64_t len) {
	subrange_t* s = (subrange_t*)apfs_calloc(1, sizeof(subrange_t));
	io_func* io = (io_func*)apfs_calloc(1, sizeof(io_func));
	s->inner = inner;
	s->off = off;
	s->len = len;
	io->data = s;
	io->read = sub_read;
	io->write = sub_write;
	io->close = sub_close;
	return io;
}
