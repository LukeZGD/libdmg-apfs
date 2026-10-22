/*
 * udif.c
 * apfs-tool
 *
 * Apple UDIF disk images. Reading supports raw, zero-fill, ignored, ADC,
 * zlib, LZFSE and (optionally) bzip2 and LZMA runs. Building reproduces the
 * layout of the APFS images shipped in IPSWs: one blkx table per GPT
 * structure and partition, 1 MiB chunks, unallocated APFS blocks stored as
 * ignored runs, and the cSum/nsiz resources that "asr imagescan" adds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "apfs/apfs.h"
#include "apfs/platform.h"
#include "apfs/udif.h"
#include "lzfse.h"

#ifdef HAVE_BZIP2
#include <bzlib.h>
#endif
#ifdef HAVE_LZMA
#include <lzma.h>
#endif

#define KOLY_SIZE 512
#define CACHE_SLOTS 8

static uint32_t be32(const uint8_t* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const uint8_t* p) {
	return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static void put_be32(uint8_t* p, uint32_t v) {
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void put_be64(uint8_t* p, uint64_t v) {
	put_be32(p, (uint32_t)(v >> 32));
	put_be32(p + 4, (uint32_t)v);
}

/* Base64 */

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64val(char c) {
	if(c >= 'A' && c <= 'Z') return c - 'A';
	if(c >= 'a' && c <= 'z') return c - 'a' + 26;
	if(c >= '0' && c <= '9') return c - '0' + 52;
	if(c == '+') return 62;
	if(c == '/') return 63;
	return -1;
}

static uint8_t* b64_decode(const char* s, size_t len, size_t* out_len) {
	uint8_t* out = (uint8_t*)apfs_malloc(len / 4 * 3 + 4);
	uint32_t acc = 0;
	int bits = 0;
	size_t n = 0, i;
	for(i = 0; i < len; i++) {
		int v = b64val(s[i]);
		if(v < 0)
			continue;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if(bits >= 8) {
			bits -= 8;
			out[n++] = (uint8_t)(acc >> bits);
		}
	}
	*out_len = n;
	return out;
}

/* Appends base64 lines of 44 characters, each prefixed with `indent` tabs */
static void b64_encode(FILE* f, const uint8_t* data, size_t len, int indent) {
	size_t i;
	int col = 0, t;
	for(i = 0; i < len; i += 3) {
		uint32_t v = (uint32_t)data[i] << 16;
		char q[4];
		int k;
		if(i + 1 < len)
			v |= (uint32_t)data[i + 1] << 8;
		if(i + 2 < len)
			v |= data[i + 2];
		q[0] = b64chars[(v >> 18) & 63];
		q[1] = b64chars[(v >> 12) & 63];
		q[2] = i + 1 < len ? b64chars[(v >> 6) & 63] : '=';
		q[3] = i + 2 < len ? b64chars[v & 63] : '=';
		for(k = 0; k < 4; k++) {
			if(col == 0)
				for(t = 0; t < indent; t++)
					fputc('\t', f);
			fputc(q[k], f);
			if(++col == 44) {
				fputc('\n', f);
				col = 0;
			}
		}
	}
	if(col)
		fputc('\n', f);
}

/* Reading */

typedef struct {
	size_t run;
	uint8_t* data;
	uint64_t stamp;
} cache_slot_t;

struct udif {
	AbstractFile* f;
	uint8_t koly[KOLY_SIZE];
	uint64_t sectors;
	udif_part_t* parts;
	int nparts;
	udif_run_t* runs;
	size_t nruns;
	cache_slot_t cache[CACHE_SLOTS];
	uint64_t stamp;
	uint32_t main_compression;
};

static int file_read_at(AbstractFile* f, uint64_t off, void* buf, size_t len) {
	if(f->seek(f, (off_t)off) != 0)
		return 0;
	return f->read(f, buf, len) == len;
}

int udif_probe(AbstractFile* f) {
	uint8_t koly[KOLY_SIZE];
	off_t len = f->getLength(f);
	if(len < KOLY_SIZE)
		return 0;
	if(!file_read_at(f, (uint64_t)len - KOLY_SIZE, koly, KOLY_SIZE))
		return 0;
	return memcmp(koly, "koly", 4) == 0;
}

/* Finds the string value following <key>name</key> inside [p, end) */
static char* dict_string(const char* p, const char* end, const char* key) {
	char pat[64];
	const char* k;
	const char* s;
	const char* e;
	char* r;
	snprintf(pat, sizeof(pat), "<key>%s</key>", key);
	k = strstr(p, pat);
	if(!k || k >= end)
		return NULL;
	s = strstr(k, "<string>");
	if(!s || s >= end)
		return NULL;
	s += 8;
	e = strstr(s, "</string>");
	if(!e || e > end)
		return NULL;
	r = (char*)apfs_malloc((size_t)(e - s) + 1);
	memcpy(r, s, (size_t)(e - s));
	r[e - s] = 0;
	return r;
}

static uint8_t* dict_data(const char* p, const char* end, size_t* len) {
	const char* k = strstr(p, "<key>Data</key>");
	const char* s;
	const char* e;
	if(!k || k >= end)
		return NULL;
	s = strstr(k, "<data>");
	if(!s || s >= end)
		return NULL;
	s += 6;
	e = strstr(s, "</data>");
	if(!e || e > end)
		return NULL;
	return b64_decode(s, (size_t)(e - s), len);
}

static int cmp_runs(const void* a, const void* b) {
	const udif_run_t* x = (const udif_run_t*)a;
	const udif_run_t* y = (const udif_run_t*)b;
	return x->sector < y->sector ? -1 : (x->sector > y->sector ? 1 : 0);
}

udif_t* udif_open(AbstractFile* f) {
	udif_t* u;
	uint64_t len, xml_off, xml_len, data_off;
	char* xml;
	char* p;
	char* arr_end;
	size_t counts[16];

	memset(counts, 0, sizeof(counts));
	len = (uint64_t)f->getLength(f);
	if(len < KOLY_SIZE)
		return NULL;
	u = (udif_t*)apfs_calloc(1, sizeof(udif_t));
	u->f = f;
	if(!file_read_at(f, len - KOLY_SIZE, u->koly, KOLY_SIZE) || memcmp(u->koly, "koly", 4) != 0) {
		free(u);
		return NULL;
	}
	data_off = be64(u->koly + 0x18);
	xml_off = be64(u->koly + 0xD8);
	xml_len = be64(u->koly + 0xE0);
	u->sectors = be64(u->koly + 0x1EC);
	if(!xml_len || xml_off + xml_len > len || xml_len > 256 * 1024 * 1024) {
		APFS_ERR("disk image has no XML property list (unsupported legacy format)");
		free(u);
		return NULL;
	}
	xml = (char*)apfs_malloc((size_t)xml_len + 1);
	if(!file_read_at(f, xml_off, xml, (size_t)xml_len)) {
		free(xml);
		free(u);
		return NULL;
	}
	xml[xml_len] = 0;

	p = strstr(xml, "<key>blkx</key>");
	arr_end = p ? strstr(p, "</array>") : NULL;
	if(!p || !arr_end) {
		APFS_ERR("disk image has no blkx resource");
		free(xml);
		free(u);
		return NULL;
	}
	for(;;) {
		char* d = strstr(p, "<dict>");
		char* de;
		uint8_t* data;
		size_t dlen;
		udif_part_t* part;
		uint32_t nruns, i;
		uint64_t first, data_start;
		char* s;

		if(!d || d > arr_end)
			break;
		de = strstr(d, "</dict>");
		if(!de || de > arr_end)
			break;
		data = dict_data(d, de, &dlen);
		if(!data || dlen < 0xCC || be32(data) != 0x6D697368 /* 'mish' */) {
			free(data);
			p = de + 7;
			continue;
		}
		u->parts = (udif_part_t*)apfs_realloc(u->parts, (u->nparts + 1) * sizeof(udif_part_t));
		part = &u->parts[u->nparts++];
		memset(part, 0, sizeof(*part));
		part->name = dict_string(d, de, "Name");
		part->cfname = dict_string(d, de, "CFName");
		s = dict_string(d, de, "ID");
		part->id = s ? atoi(s) : 0;
		free(s);
		s = dict_string(d, de, "Attributes");
		part->attributes = s ? (uint32_t)strtoul(s, NULL, 0) : 0;
		free(s);
		first = be64(data + 8);
		part->first_sector = first;
		part->sector_count = be64(data + 16);
		data_start = be64(data + 24);
		part->checksum_type = be32(data + 0x40);
		part->checksum = be32(data + 0x48);
		nruns = be32(data + 0xC8);
		if(0xCC + (uint64_t)nruns * 40 > dlen)
			nruns = (uint32_t)((dlen - 0xCC) / 40);
		for(i = 0; i < nruns; i++) {
			const uint8_t* r = data + 0xCC + i * 40;
			uint32_t type = be32(r);
			udif_run_t* run;
			if(type == UDIF_TERMINATOR || type == UDIF_COMMENT)
				continue;
			u->runs = (udif_run_t*)apfs_realloc(u->runs, (u->nruns + 1) * sizeof(udif_run_t));
			run = &u->runs[u->nruns++];
			run->type = type;
			run->sector = first + be64(r + 8);
			run->count = be64(r + 16);
			run->offset = data_off + data_start + be64(r + 24);
			run->length = be64(r + 32);
			if(type & 0x80000000U)
				counts[type & 0xf]++;
		}
		free(data);
		p = de + 7;
	}
	free(xml);
	if(!u->nruns) {
		udif_close(u);
		return NULL;
	}
	qsort(u->runs, u->nruns, sizeof(udif_run_t), cmp_runs);
	{
		size_t best = 0, i;
		for(i = 0; i < 16; i++)
			if(counts[i] > counts[best])
				best = i;
		u->main_compression = counts[best] ? (0x80000000U | (uint32_t)best) : UDIF_RAW;
	}
	if(!u->sectors && u->nruns)
		u->sectors = u->runs[u->nruns - 1].sector + u->runs[u->nruns - 1].count;
	return u;
}

void udif_close(udif_t* u) {
	int i;
	if(!u)
		return;
	for(i = 0; i < u->nparts; i++) {
		free(u->parts[i].name);
		free(u->parts[i].cfname);
	}
	free(u->parts);
	free(u->runs);
	for(i = 0; i < CACHE_SLOTS; i++)
		free(u->cache[i].data);
	if(u->f)
		u->f->close(u->f);
	free(u);
}

uint64_t udif_sectors(udif_t* u) {
	return u->sectors;
}

int udif_parts(udif_t* u, udif_part_t** parts, int* count) {
	*parts = u->parts;
	*count = u->nparts;
	return APFS_OK;
}

uint32_t udif_main_compression(udif_t* u) {
	return u->main_compression;
}

const char* udif_format_name(uint32_t c) {
	switch(c) {
		case UDIF_ZLIB: return "UDZO";
		case UDIF_LZFSE: return "ULFO";
		case UDIF_BZIP2: return "UDBZ";
		case UDIF_LZMA: return "ULMO";
		case UDIF_ADC: return "UDCO";
		case UDIF_RAW: return "UDRO";
		default: return "unknown";
	}
}

static size_t adc_decode(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len) {
	size_t ip = 0, op = 0;
	while(ip < in_len && op < out_len) {
		uint8_t b = in[ip++];
		if(b & 0x80) {
			size_t n = (size_t)(b & 0x7f) + 1;
			if(ip + n > in_len || op + n > out_len)
				return 0;
			memcpy(out + op, in + ip, n);
			ip += n;
			op += n;
		} else {
			size_t n, off, k;
			if(b & 0x40) {
				if(ip + 2 > in_len)
					return 0;
				n = (size_t)(b & 0x3f) + 4;
				off = ((size_t)in[ip] << 8 | in[ip + 1]) + 1;
				ip += 2;
			} else {
				if(ip + 1 > in_len)
					return 0;
				n = (size_t)((b >> 2) & 0xf) + 3;
				off = ((size_t)(b & 3) << 8 | in[ip]) + 1;
				ip += 1;
			}
			if(off > op || op + n > out_len)
				return 0;
			for(k = 0; k < n; k++, op++)
				out[op] = out[op - off];
		}
	}
	return op;
}

static int decode_run(udif_t* u, const udif_run_t* r, uint8_t* out) {
	size_t out_len = (size_t)(r->count * UDIF_SECTOR);
	uint8_t* in;
	size_t got = 0;
	int ok = 0;

	switch(r->type) {
		case UDIF_ZERO:
		case UDIF_IGNORE:
			memset(out, 0, out_len);
			return APFS_OK;
		case UDIF_RAW:
			if(r->length < out_len)
				memset(out + r->length, 0, out_len - (size_t)r->length);
			return file_read_at(u->f, r->offset, out, (size_t)(r->length < out_len ? r->length : out_len)) ? APFS_OK : APFS_EIO;
		default:
			break;
	}
	if(r->length > 64 * 1024 * 1024)
		return APFS_ECORRUPT;
	in = (uint8_t*)apfs_malloc((size_t)r->length + 1);
	if(!file_read_at(u->f, r->offset, in, (size_t)r->length)) {
		free(in);
		return APFS_EIO;
	}
	switch(r->type) {
		case UDIF_ZLIB: {
			z_stream s;
			memset(&s, 0, sizeof(s));
			if(inflateInit(&s) == Z_OK) {
				int zr;
				s.next_in = in;
				s.avail_in = (uInt)r->length;
				s.next_out = out;
				s.avail_out = (uInt)out_len;
				zr = inflate(&s, Z_FINISH);
				got = out_len - s.avail_out;
				ok = (zr == Z_STREAM_END || zr == Z_OK || zr == Z_BUF_ERROR);
				inflateEnd(&s);
			}
			break;
		}
		case UDIF_LZFSE: {
			void* scratch = apfs_malloc(lzfse_decode_scratch_size() + 1);
			got = lzfse_decode_buffer(out, out_len, in, (size_t)r->length, scratch);
			free(scratch);
			ok = 1;
			break;
		}
		case UDIF_ADC:
			got = adc_decode(in, (size_t)r->length, out, out_len);
			ok = 1;
			break;
#ifdef HAVE_BZIP2
		case UDIF_BZIP2: {
			unsigned int dl = (unsigned int)out_len;
			ok = BZ2_bzBuffToBuffDecompress((char*)out, &dl, (char*)in, (unsigned int)r->length, 0, 0) == BZ_OK;
			got = dl;
			break;
		}
#endif
#ifdef HAVE_LZMA
		case UDIF_LZMA: {
			uint64_t memlimit = UINT64_MAX;
			size_t inpos = 0, outpos = 0;
			ok = lzma_stream_buffer_decode(&memlimit, 0, NULL, in, &inpos, (size_t)r->length, out, &outpos, out_len) == LZMA_OK;
			got = outpos;
			break;
		}
#endif
		default:
			APFS_ERR("unsupported UDIF chunk type 0x%08x", r->type);
			free(in);
			return APFS_EUNSUPP;
	}
	free(in);
	if(!ok)
		return APFS_ECORRUPT;
	if(got < out_len)
		memset(out + got, 0, out_len - got);
	return APFS_OK;
}

static const udif_run_t* find_run(udif_t* u, uint64_t sector, size_t* idx) {
	size_t lo = 0, hi = u->nruns;
	while(lo < hi) {
		size_t mid = (lo + hi) / 2;
		const udif_run_t* r = &u->runs[mid];
		if(sector < r->sector)
			hi = mid;
		else if(sector >= r->sector + r->count)
			lo = mid + 1;
		else {
			*idx = mid;
			return r;
		}
	}
	return NULL;
}

static const uint8_t* cached_run(udif_t* u, size_t idx) {
	int i, victim = 0;
	for(i = 0; i < CACHE_SLOTS; i++) {
		if(u->cache[i].data && u->cache[i].run == idx) {
			u->cache[i].stamp = ++u->stamp;
			return u->cache[i].data;
		}
		if(!u->cache[victim].data)
			continue;
		if(!u->cache[i].data || u->cache[i].stamp < u->cache[victim].stamp)
			victim = i;
	}
	free(u->cache[victim].data);
	u->cache[victim].data = (uint8_t*)apfs_malloc((size_t)(u->runs[idx].count * UDIF_SECTOR) + 1);
	if(decode_run(u, &u->runs[idx], u->cache[victim].data) < 0) {
		free(u->cache[victim].data);
		u->cache[victim].data = NULL;
		return NULL;
	}
	u->cache[victim].run = idx;
	u->cache[victim].stamp = ++u->stamp;
	return u->cache[victim].data;
}

static int udif_io_read(io_func* io, off_t location, size_t size, void* buffer) {
	udif_t* u = (udif_t*)io->data;
	uint8_t* out = (uint8_t*)buffer;
	uint64_t pos = (uint64_t)location;

	while(size > 0) {
		uint64_t sector = pos / UDIF_SECTOR;
		size_t idx, n;
		const udif_run_t* r = find_run(u, sector, &idx);
		if(!r) {
			/* outside every run: zero */
			n = UDIF_SECTOR - (size_t)(pos % UDIF_SECTOR);
			if(n > size)
				n = size;
			memset(out, 0, n);
		} else {
			uint64_t run_start = r->sector * UDIF_SECTOR;
			uint64_t run_end = (r->sector + r->count) * UDIF_SECTOR;
			n = (size_t)(run_end - pos);
			if(n > size)
				n = size;
			if(r->type == UDIF_ZERO || r->type == UDIF_IGNORE) {
				memset(out, 0, n);
			} else if(r->type == UDIF_RAW) {
				uint64_t within = pos - run_start;
				if(within + n <= r->length) {
					if(!file_read_at(u->f, r->offset + within, out, n))
						return FALSE;
				} else {
					const uint8_t* d = cached_run(u, idx);
					if(!d)
						return FALSE;
					memcpy(out, d + within, n);
				}
			} else {
				const uint8_t* d = cached_run(u, idx);
				if(!d)
					return FALSE;
				memcpy(out, d + (pos - run_start), n);
			}
		}
		out += n;
		pos += n;
		size -= n;
	}
	return TRUE;
}

static int udif_io_write(io_func* io, off_t location, size_t size, void* buffer) {
	(void)io;
	(void)location;
	(void)size;
	(void)buffer;
	return FALSE;
}

static void udif_io_close(io_func* io) {
	udif_close((udif_t*)io->data);
	free(io);
}

io_func* udif_io(udif_t* u) {
	io_func* io = (io_func*)apfs_calloc(1, sizeof(io_func));
	io->data = u;
	io->read = udif_io_read;
	io->write = udif_io_write;
	io->close = udif_io_close;
	return io;
}

int udif_verify(udif_t* u, int verbose) {
	int i, bad = 0;
	uint8_t* buf = NULL;
	size_t cap = 0, k;

	for(i = 0; i < u->nparts; i++) {
		udif_part_t* p = &u->parts[i];
		uint32_t crc = 0;
		if(p->checksum_type != 2)
			continue;
		for(k = 0; k < u->nruns; k++) {
			udif_run_t* r = &u->runs[k];
			size_t len;
			if(r->sector < p->first_sector || r->sector >= p->first_sector + p->sector_count || r->type == UDIF_IGNORE)
				continue;
			len = (size_t)(r->count * UDIF_SECTOR);
			if(len > cap) {
				cap = len;
				buf = (uint8_t*)apfs_realloc(buf, cap);
			}
			if(decode_run(u, r, buf) < 0) {
				free(buf);
				return APFS_ECORRUPT;
			}
			crc = (uint32_t)crc32(crc, buf, (uInt)len);
		}
		if(crc != p->checksum)
			bad++;
		if(verbose || crc != p->checksum)
			printf("%-28s CRC32 $%08X %s\n", p->name ? p->name : "?", p->checksum, crc == p->checksum ? "verified" : "MISMATCH");
	}
	free(buf);
	return bad ? APFS_ECORRUPT : APFS_OK;
}

/* Decompresses the whole disk, or with part >= 0 that partition, into out,
 * which must be a new file: empty runs and blocks of zeros are left as holes */
int udif_extract(udif_t* u, int part, FILE* out, int quiet) {
	size_t i;
	uint8_t* buf = NULL;
	size_t cap = 0;
	uint64_t first = part >= 0 ? u->parts[part].first_sector : 0;
	uint64_t sectors = part >= 0 ? u->parts[part].sector_count : u->sectors;
	if(plat_sparse_file(out, sectors * UDIF_SECTOR) < 0)
		return APFS_EIO;
	for(i = 0; i < u->nruns; i++) {
		udif_run_t* r = &u->runs[i];
		size_t len = (size_t)(r->count * UDIF_SECTOR);
		int ret;
		if(r->type == UDIF_IGNORE || r->type == UDIF_ZERO || !r->count || r->sector < first || r->sector >= first + sectors)
			continue;
		if(len > cap) {
			cap = len;
			buf = (uint8_t*)apfs_realloc(buf, cap);
		}
		ret = decode_run(u, r, buf);
		if(ret == APFS_OK)
			ret = plat_write_sparse(out, (r->sector - first) * UDIF_SECTOR, buf, len);
		if(ret < 0) {
			free(buf);
			return ret;
		}
		if(!quiet && (i % 256) == 0) {
			printf("\rExtracting... %3d%%", (int)(i * 100 / u->nruns));
			fflush(stdout);
		}
	}
	free(buf);
	if(!quiet)
		printf("\rExtracting... done\n");
	return plat_sparse_finish(out);
}

/* MediaKit block checksum, used by the cSum and nsiz resources */
uint32_t udif_mkblock_checksum(uint32_t ck, const uint8_t* data, size_t len) {
	size_t i;
	for(i = 0; i + 4 <= len; i += 4)
		ck = be32(data + i) + ((ck >> 31) | (ck << 1));
	return ck;
}

/* GPT */

static const uint8_t gpt_apfs_type[16] = {
	0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC
};

typedef struct {
	io_func* inner;
	uint64_t container_bytes;
	uint64_t total_sectors;
	uint8_t head[34 * UDIF_SECTOR];   /* MBR, header, entries */
	uint8_t tail[33 * UDIF_SECTOR];   /* entries, backup header */
} gptwrap_t;

static void gpt_header(uint8_t* h, uint64_t current, uint64_t backup, uint64_t first_usable, uint64_t last_usable,
		const uint8_t* disk_guid, uint64_t entries_lba, uint32_t entries_crc) {
	uint32_t crc;
	memset(h, 0, UDIF_SECTOR);
	memcpy(h, "EFI PART", 8);
	apfs_put32(h + 8, 0x00010000);
	apfs_put32(h + 12, 92);
	apfs_put64(h + 24, current);
	apfs_put64(h + 32, backup);
	apfs_put64(h + 40, first_usable);
	apfs_put64(h + 48, last_usable);
	memcpy(h + 56, disk_guid, 16);
	apfs_put64(h + 72, entries_lba);
	apfs_put32(h + 80, 128);
	apfs_put32(h + 84, 128);
	apfs_put32(h + 88, entries_crc);
	crc = (uint32_t)crc32(0, h, 92);
	apfs_put32(h + 16, crc);
}

static void uuid_to_guid(const uint8_t* u, uint8_t* g) {
	/* GPT stores the first three fields little-endian */
	g[0] = u[3]; g[1] = u[2]; g[2] = u[1]; g[3] = u[0];
	g[4] = u[5]; g[5] = u[4];
	g[6] = u[7]; g[7] = u[6];
	memcpy(g + 8, u + 8, 8);
}

static int gptwrap_read(io_func* io, off_t location, size_t size, void* buffer) {
	gptwrap_t* w = (gptwrap_t*)io->data;
	uint8_t* out = (uint8_t*)buffer;
	uint64_t pos = (uint64_t)location;
	uint64_t data_start = 34 * UDIF_SECTOR;
	uint64_t data_end = data_start + w->container_bytes;
	uint64_t total = w->total_sectors * UDIF_SECTOR;

	while(size > 0) {
		size_t n;
		if(pos < data_start) {
			n = (size_t)(data_start - pos);
			if(n > size)
				n = size;
			memcpy(out, w->head + pos, n);
		} else if(pos < data_end) {
			n = (size_t)(data_end - pos);
			if(n > size)
				n = size;
			if(!w->inner->read(w->inner, (off_t)(pos - data_start), n, out))
				return FALSE;
		} else if(pos < total) {
			n = (size_t)(total - pos);
			if(n > size)
				n = size;
			memcpy(out, w->tail + (pos - data_end), n);
		} else {
			n = size;
			memset(out, 0, n);
		}
		out += n;
		pos += n;
		size -= n;
	}
	return TRUE;
}

static void gptwrap_close(io_func* io) {
	free(io->data);
	free(io);
}

io_func* udif_gpt_wrap(io_func* container, uint64_t container_bytes, uint64_t* disk_bytes) {
	gptwrap_t* w = (gptwrap_t*)apfs_calloc(1, sizeof(gptwrap_t));
	io_func* io;
	uint64_t part_sectors = (container_bytes + UDIF_SECTOR - 1) / UDIF_SECTOR;
	uint64_t total = 34 + part_sectors + 33;
	uint8_t uuid[16], guid[16];
	uint8_t* entries = w->head + 2 * UDIF_SECTOR;
	uint32_t ecrc;

	w->inner = container;
	w->container_bytes = part_sectors * UDIF_SECTOR;
	w->total_sectors = total;

	/* protective MBR */
	{
		uint8_t* m = w->head + 446;
		uint64_t n = total - 1 > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : total - 1;
		m[0] = 0x00;
		m[1] = 0xFE; m[2] = 0xFF; m[3] = 0xFF;
		m[4] = 0xEE;
		m[5] = 0xFE; m[6] = 0xFF; m[7] = 0xFF;
		apfs_put32(m + 8, 1);
		apfs_put32(m + 12, (uint32_t)n);
		w->head[510] = 0x55;
		w->head[511] = 0xAA;
	}

	/* partition entry */
	memcpy(entries, gpt_apfs_type, 16);
	apfs_uuid_generate(uuid);
	uuid_to_guid(uuid, guid);
	memcpy(entries + 16, guid, 16);
	apfs_put64(entries + 32, 34);
	apfs_put64(entries + 40, 34 + part_sectors - 1);
	ecrc = (uint32_t)crc32(0, entries, 128 * 128);
	memcpy(w->tail, entries, 32 * UDIF_SECTOR);

	apfs_uuid_generate(uuid);
	uuid_to_guid(uuid, guid);
	gpt_header(w->head + UDIF_SECTOR, 1, total - 1, 34, total - 34, guid, 2, ecrc);
	gpt_header(w->tail + 32 * UDIF_SECTOR, total - 1, 1, 34, total - 34, guid, total - 33, ecrc);

	io = (io_func*)apfs_calloc(1, sizeof(io_func));
	io->data = w;
	io->read = gptwrap_read;
	io->write = udif_io_write;
	io->close = gptwrap_close;
	*disk_bytes = total * UDIF_SECTOR;
	return io;
}

int udif_gpt_find(io_func* disk, uint64_t disk_bytes, uint64_t* part_offset, uint64_t* part_length, int* part_index) {
	uint8_t h[UDIF_SECTOR];
	uint8_t* entries;
	uint32_t count, esize, i;
	uint64_t lba;
	(void)disk_bytes;

	if(!disk->read(disk, UDIF_SECTOR, UDIF_SECTOR, h) || memcmp(h, "EFI PART", 8) != 0)
		return APFS_ENOENT;
	lba = apfs_get64(h + 72);
	count = apfs_get32(h + 80);
	esize = apfs_get32(h + 84);
	if(esize < 128 || esize > 4096 || !count || count > 1024)
		return APFS_ECORRUPT;
	entries = (uint8_t*)apfs_malloc((size_t)count * esize);
	if(!disk->read(disk, (off_t)(lba * UDIF_SECTOR), (size_t)count * esize, entries)) {
		free(entries);
		return APFS_EIO;
	}
	for(i = 0; i < count; i++) {
		uint8_t* e = entries + (size_t)i * esize;
		if(memcmp(e, gpt_apfs_type, 16) == 0) {
			*part_offset = apfs_get64(e + 32) * UDIF_SECTOR;
			*part_length = (apfs_get64(e + 40) - apfs_get64(e + 32) + 1) * UDIF_SECTOR;
			if(part_index)
				*part_index = (int)i;
			free(entries);
			return APFS_OK;
		}
	}
	free(entries);
	return APFS_ENOENT;
}

/* Moves the backup GPT to the new end of the disk and resizes one partition */
int udif_gpt_resize(io_func* disk, uint64_t old_bytes, uint64_t new_bytes, int part_index, uint64_t new_part_length) {
	uint8_t h[UDIF_SECTOR];
	uint8_t tail[33 * UDIF_SECTOR];
	uint8_t* entries;
	uint64_t total = new_bytes / UDIF_SECTOR;
	uint32_t ecrc;
	uint8_t guid[16];
	uint8_t zero[UDIF_SECTOR];
	(void)old_bytes;

	if(!disk->read(disk, UDIF_SECTOR, UDIF_SECTOR, h) || memcmp(h, "EFI PART", 8) != 0)
		return APFS_ENOENT;
	memcpy(guid, h + 56, 16);
	entries = (uint8_t*)apfs_malloc(32 * UDIF_SECTOR);
	if(!disk->read(disk, 2 * UDIF_SECTOR, 32 * UDIF_SECTOR, entries)) {
		free(entries);
		return APFS_EIO;
	}
	{
		uint8_t* e = entries + (size_t)part_index * 128;
		uint64_t first = apfs_get64(e + 32);
		apfs_put64(e + 40, first + new_part_length / UDIF_SECTOR - 1);
	}
	ecrc = (uint32_t)crc32(0, entries, 128 * 128);
	gpt_header(h, 1, total - 1, 34, total - 34, guid, 2, ecrc);
	memcpy(tail, entries, 32 * UDIF_SECTOR);
	gpt_header(tail + 32 * UDIF_SECTOR, total - 1, 1, 34, total - 34, guid, total - 33, ecrc);
	memset(zero, 0, sizeof(zero));
	if(!disk->write(disk, UDIF_SECTOR, UDIF_SECTOR, h) || !disk->write(disk, 2 * UDIF_SECTOR, 32 * UDIF_SECTOR, entries) ||
			!disk->write(disk, (off_t)((total - 33) * UDIF_SECTOR), 33 * UDIF_SECTOR, tail)) {
		free(entries);
		return APFS_EIO;
	}
	/* protective MBR size */
	{
		uint8_t mbr[UDIF_SECTOR];
		if(disk->read(disk, 0, UDIF_SECTOR, mbr) && mbr[446 + 4] == 0xEE) {
			uint64_t n = total - 1 > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : total - 1;
			apfs_put32(mbr + 446 + 12, (uint32_t)n);
			disk->write(disk, 0, UDIF_SECTOR, mbr);
		}
	}
	free(entries);
	return APFS_OK;
}

/* Building */

void udif_default_opts(udif_build_opts_t* o) {
	memset(o, 0, sizeof(*o));
	o->compression = UDIF_ZLIB;
	o->level = 9;
	o->chunk_sectors = 2048;
	o->imagescan = 1;
}

typedef struct {
	char name[64];
	uint64_t first;
	uint64_t count;
	int is_apfs;
	int is_free;
} region_t;

/* Splits a disk into the regions that get their own blkx table */
static int disk_regions(io_func* disk, uint64_t total, region_t** out, int* count) {
	uint8_t h[UDIF_SECTOR];
	region_t* r = NULL;
	int n = 0;

	if(disk->read(disk, UDIF_SECTOR, UDIF_SECTOR, h) && memcmp(h, "EFI PART", 8) == 0) {
		uint64_t elba = apfs_get64(h + 72), backup = apfs_get64(h + 32);
		uint32_t ecount = apfs_get32(h + 80), esize = apfs_get32(h + 84), i;
		uint64_t table_sectors = ((uint64_t)ecount * esize + UDIF_SECTOR - 1) / UDIF_SECTOR;
		uint8_t* entries;
		uint64_t cursor;
		uint64_t parts[256][3];
		int np = 0, j;

		if(esize < 128 || esize > 4096 || ecount == 0 || ecount > 1024 || backup != total - 1 || elba != 2)
			goto bare;
		entries = (uint8_t*)apfs_malloc((size_t)(table_sectors * UDIF_SECTOR));
		if(!disk->read(disk, (off_t)(elba * UDIF_SECTOR), (size_t)(table_sectors * UDIF_SECTOR), entries)) {
			free(entries);
			goto bare;
		}
		for(i = 0; i < ecount && np < 256; i++) {
			uint8_t* e = entries + (size_t)i * esize;
			static const uint8_t zero[16] = { 0 };
			if(!memcmp(e, zero, 16))
				continue;
			parts[np][0] = apfs_get64(e + 32);
			parts[np][1] = apfs_get64(e + 40) - apfs_get64(e + 32) + 1;
			parts[np][2] = memcmp(e, gpt_apfs_type, 16) == 0;
			np++;
		}
		free(entries);

		r = (region_t*)apfs_calloc((size_t)(np * 2 + 6), sizeof(region_t));
		strcpy(r[n].name, "MBR"); r[n].first = 0; r[n].count = 1; n++;
		strcpy(r[n].name, "Primary GPT Header"); r[n].first = 1; r[n].count = 1; n++;
		strcpy(r[n].name, "Primary GPT Table"); r[n].first = 2; r[n].count = table_sectors; n++;
		cursor = 2 + table_sectors;
		/* partitions in disk order */
		for(i = 0; i < (uint32_t)np; i++) {
			for(j = (int)i + 1; j < np; j++) {
				if(parts[j][0] < parts[i][0]) {
					uint64_t t[3];
					memcpy(t, parts[i], sizeof(t));
					memcpy(parts[i], parts[j], sizeof(t));
					memcpy(parts[j], t, sizeof(t));
				}
			}
		}
		for(i = 0; i < (uint32_t)np; i++) {
			if(parts[i][0] > cursor) {
				strcpy(r[n].name, "Apple_Free");
				r[n].first = cursor;
				r[n].count = parts[i][0] - cursor;
				r[n].is_free = 1;
				n++;
			}
			strcpy(r[n].name, parts[i][2] ? "Apple_APFS" : "Untitled");
			r[n].first = parts[i][0];
			r[n].count = parts[i][1];
			r[n].is_apfs = (int)parts[i][2];
			n++;
			cursor = parts[i][0] + parts[i][1];
		}
		if(total - 1 - table_sectors > cursor) {
			strcpy(r[n].name, "Apple_Free");
			r[n].first = cursor;
			r[n].count = total - 1 - table_sectors - cursor;
			r[n].is_free = 1;
			n++;
		}
		strcpy(r[n].name, "Backup GPT Table"); r[n].first = total - 1 - table_sectors; r[n].count = table_sectors; n++;
		strcpy(r[n].name, "Backup GPT Header"); r[n].first = total - 1; r[n].count = 1; n++;
		*out = r;
		*count = n;
		return APFS_OK;
	}
bare:
	r = (region_t*)apfs_calloc(1, sizeof(region_t));
	strcpy(r[0].name, "Apple_APFS");
	r[0].first = 0;
	r[0].count = total;
	r[0].is_apfs = 1;
	*out = r;
	*count = 1;
	return APFS_OK;
}

typedef struct {
	uint8_t* tbl;              /* blkx table being built */
	size_t cap;
	uint32_t nruns;
} blkx_buf_t;

static void blkx_add_run(blkx_buf_t* b, uint32_t type, uint64_t sector_start, uint64_t count, uint64_t off, uint64_t len) {
	size_t need = 0xCC + (size_t)(b->nruns + 1) * 40;
	uint8_t* r;
	if(need > b->cap) {
		b->cap = need * 2;
		b->tbl = (uint8_t*)apfs_realloc(b->tbl, b->cap);
	}
	r = b->tbl + 0xCC + (size_t)b->nruns * 40;
	memset(r, 0, 40);
	put_be32(r, type);
	put_be64(r + 8, sector_start);
	put_be64(r + 16, count);
	put_be64(r + 24, off);
	put_be64(r + 32, len);
	b->nruns++;
}

static size_t compress_chunk(uint32_t type, int level, const uint8_t* in, size_t len, uint8_t* out, size_t cap) {
	switch(type) {
		case UDIF_ZLIB: {
			uLongf n = (uLongf)cap;
			if(compress2(out, &n, in, (uLong)len, level) != Z_OK)
				return 0;
			return n;
		}
		case UDIF_LZFSE: {
			void* scratch = apfs_malloc(lzfse_encode_scratch_size() + 1);
			size_t n = lzfse_encode_buffer(out, cap, in, len, scratch);
			free(scratch);
			return n;
		}
#ifdef HAVE_BZIP2
		case UDIF_BZIP2: {
			unsigned int n = (unsigned int)cap;
			if(BZ2_bzBuffToBuffCompress((char*)out, &n, (char*)in, (unsigned int)len, 9, 0, 0) != BZ_OK)
				return 0;
			return n;
		}
#endif
#ifdef HAVE_LZMA
		case UDIF_LZMA: {
			size_t pos = 0;
			if(lzma_easy_buffer_encode(6, LZMA_CHECK_CRC64, NULL, in, len, out, &pos, cap) != LZMA_OK)
				return 0;
			return pos;
		}
#endif
		default:
			return 0;
	}
}

typedef struct {
	FILE* out;
	uint64_t pos;
	uint32_t fork_crc;
} writer_t;

static int emit(writer_t* w, const void* data, size_t len) {
	if(fwrite(data, 1, len, w->out) != len)
		return APFS_EIO;
	w->fork_crc = (uint32_t)crc32(w->fork_crc, (const Bytef*)data, (uInt)len);
	w->pos += len;
	return APFS_OK;
}

typedef struct {
	char* name;
	uint8_t* tbl;
	size_t len;
	uint32_t crc;
	int id;
} done_blkx_t;

static void xml_dict(FILE* f, const char* attributes, const char* cfname, const uint8_t* data, size_t len, int id, const char* name) {
	fprintf(f, "\t\t\t<dict>\n");
	fprintf(f, "\t\t\t\t<key>Attributes</key>\n\t\t\t\t<string>%s</string>\n", attributes);
	if(cfname)
		fprintf(f, "\t\t\t\t<key>CFName</key>\n\t\t\t\t<string>%s</string>\n", cfname);
	fprintf(f, "\t\t\t\t<key>Data</key>\n\t\t\t\t<data>\n");
	b64_encode(f, data, len, 4);
	fprintf(f, "\t\t\t\t</data>\n");
	fprintf(f, "\t\t\t\t<key>ID</key>\n\t\t\t\t<string>%d</string>\n", id);
	fprintf(f, "\t\t\t\t<key>Name</key>\n\t\t\t\t<string>%s</string>\n", name);
	fprintf(f, "\t\t\t</dict>\n");
}

static const uint8_t plst_data[1032] = {
	[514] = 0x01, [516] = 0x01
};

int udif_build(io_func* disk, uint64_t disk_bytes, FILE* out, const udif_build_opts_t* o) {
	writer_t w;
	region_t* regions;
	int nregions, i, ret = APFS_OK;
	uint64_t total = (disk_bytes + UDIF_SECTOR - 1) / UDIF_SECTOR;
	uint32_t chunk = o->chunk_sectors ? o->chunk_sectors : 2048;
	uint8_t* in = (uint8_t*)apfs_malloc((size_t)chunk * UDIF_SECTOR);
	size_t outcap = (size_t)chunk * UDIF_SECTOR * 2 + 4096;
	uint8_t* cbuf = (uint8_t*)apfs_malloc(outcap);
	done_blkx_t* done;
	apfs_sha1_ctx sha1;
	apfs_sha256_ctx sha256;
	uint32_t mkblock = 0;
	uint8_t koly[KOLY_SIZE];
	uint64_t xml_off;
	char* xml_buf = NULL;
	size_t xml_len = 0;
	FILE* xf;

	memset(&w, 0, sizeof(w));
	w.out = out;
	apfs_sha1_init(&sha1);
	apfs_sha256_init(&sha256);

	disk_regions(disk, total, &regions, &nregions);
	done = (done_blkx_t*)apfs_calloc((size_t)nregions, sizeof(done_blkx_t));

	for(i = 0; i < nregions && ret == APFS_OK; i++) {
		region_t* rg = &regions[i];
		blkx_buf_t b;
		uint64_t s = 0;
		uint32_t crc = 0;
		uint32_t max_run = 0;
		int scan = o->imagescan && rg->is_apfs;

		memset(&b, 0, sizeof(b));
		b.cap = 0xCC + 40 * 16;
		b.tbl = (uint8_t*)apfs_calloc(1, b.cap);

		if(!o->quiet)
			printf("Writing %s (%llu sectors)...\n", rg->name, (unsigned long long)rg->count);

		while(s < rg->count && ret == APFS_OK) {
			uint64_t n = rg->count - s;
			if(n > chunk)
				n = chunk;
			/* unallocated APFS blocks become ignored runs, split exactly at allocation boundaries */
			if((rg->is_apfs && o->is_free) || rg->is_free) {
				uint64_t byte = s * UDIF_SECTOR; /* offset inside the partition */
				uint64_t f = 0;
				const uint64_t step = 8; /* one 4 KiB block */
				if(rg->is_free) {
					f = rg->count - s;
				} else {
					while(s + f < rg->count && f < ((uint64_t)1 << 32) &&
							o->is_free(o->free_ctx, byte + f * UDIF_SECTOR, step * UDIF_SECTOR))
						f += step;
					if(s + f > rg->count)
						f = rg->count - s;
				}
				if(f) {
					blkx_add_run(&b, UDIF_IGNORE, s, f, w.pos, 0);
					s += f;
					continue;
				}
				/* used data up to the next free block */
				{
					uint64_t u = step;
					while(u < n && !o->is_free(o->free_ctx, byte + u * UDIF_SECTOR, step * UDIF_SECTOR))
						u += step;
					if(u < n)
						n = u;
				}
			}

			if(!disk->read(disk, (off_t)((rg->first + s) * UDIF_SECTOR), (size_t)(n * UDIF_SECTOR), in)) {
				ret = APFS_EIO;
				break;
			}
			crc = (uint32_t)crc32(crc, in, (uInt)(n * UDIF_SECTOR));
			if(scan) {
				apfs_sha1_update(&sha1, in, (size_t)(n * UDIF_SECTOR));
				apfs_sha256_update(&sha256, in, (size_t)(n * UDIF_SECTOR));
				mkblock = udif_mkblock_checksum(mkblock, in, (size_t)(n * UDIF_SECTOR));
			}
			{
				size_t clen = 0;
				if(o->compression != UDIF_RAW)
					clen = compress_chunk(o->compression, o->level ? o->level : 9, in, (size_t)(n * UDIF_SECTOR), cbuf, outcap);
				if(clen && clen < n * UDIF_SECTOR) {
					blkx_add_run(&b, o->compression, s, n, w.pos, clen);
					ret = emit(&w, cbuf, clen);
				} else {
					blkx_add_run(&b, UDIF_RAW, s, n, w.pos, n * UDIF_SECTOR);
					ret = emit(&w, in, (size_t)(n * UDIF_SECTOR));
				}
			}
			if(n > max_run)
				max_run = (uint32_t)n;
			s += n;
		}
		blkx_add_run(&b, UDIF_TERMINATOR, rg->count, 0, w.pos, 0);

		/* table header */
		put_be32(b.tbl, 0x6D697368); /* 'mish' */
		put_be32(b.tbl + 4, 1);
		put_be64(b.tbl + 8, rg->first);
		put_be64(b.tbl + 16, rg->count);
		put_be64(b.tbl + 24, 0);
		put_be32(b.tbl + 32, (max_run ? max_run : 1) + 1);
		put_be32(b.tbl + 36, (uint32_t)i);
		put_be32(b.tbl + 0x40, 2);
		put_be32(b.tbl + 0x44, 32);
		put_be32(b.tbl + 0x48, crc);
		put_be32(b.tbl + 0xC8, b.nruns);
		done[i].name = rg->name;
		done[i].tbl = b.tbl;
		done[i].len = 0xCC + (size_t)b.nruns * 40;
		done[i].crc = crc;
		done[i].id = i;
	}
	free(in);
	free(cbuf);

	if(ret == APFS_OK) {
		uint32_t master = 0;
		uint8_t sha1d[20], sha256d[32];
		apfs_sha1_final(&sha1, sha1d);
		apfs_sha256_final(&sha256, sha256d);

		xf = tmpfile();
		if(!xf) {
			ret = APFS_EIO;
		} else {
			fprintf(xf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
			fprintf(xf, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
			fprintf(xf, "<plist version=\"1.0\">\n<dict>\n\t<key>resource-fork</key>\n\t<dict>\n");
			fprintf(xf, "\t\t<key>blkx</key>\n\t\t<array>\n");
			for(i = 0; i < nregions; i++) {
				uint8_t be[4];
				xml_dict(xf, "0x0050", done[i].name, done[i].tbl, done[i].len, done[i].id, done[i].name);
				put_be32(be, done[i].crc);
				master = (uint32_t)crc32(master, be, 4);
			}
			fprintf(xf, "\t\t</array>\n");
			if(o->imagescan) {
				uint8_t csum[10];
				char* nsiz;
				size_t nlen = 0;
				int v;
				FILE* nf;
				apfs_put16(csum, 1);
				apfs_put32(csum + 2, 2);
				apfs_put32(csum + 6, mkblock);
				fprintf(xf, "\t\t<key>cSum</key>\n\t\t<array>\n");
				xml_dict(xf, "0x0000", NULL, csum, sizeof(csum), 0, "");
				fprintf(xf, "\t\t</array>\n");

				nf = tmpfile();
				if(nf) {
					fprintf(nf, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
					fprintf(nf, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
					fprintf(nf, "<plist version=\"1.0\">\n<dict>\n");
					fprintf(nf, "\t<key>SHA-1-digest</key>\n\t<data>\n");
					b64_encode(nf, sha1d, sizeof(sha1d), 1);
					fprintf(nf, "\t</data>\n\t<key>SHA-256-digest</key>\n\t<data>\n");
					b64_encode(nf, sha256d, sizeof(sha256d), 1);
					fprintf(nf, "\t</data>\n");
					if(o->nvolumes) {
						fprintf(nf, "\t<key>Volume names and UUIDs</key>\n\t<array>\n");
						for(v = 0; v < o->nvolumes; v++)
							fprintf(nf, "\t\t<dict>\n\t\t\t<key>name</key>\n\t\t\t<string>%s</string>\n\t\t\t<key>uuid</key>\n\t\t\t<string>%s</string>\n\t\t</dict>\n",
								o->volume_names[v], o->volume_uuids[v]);
						fprintf(nf, "\t</array>\n");
					}
					fprintf(nf, "\t<key>block-checksum-2</key>\n\t<integer>%d</integer>\n", (int32_t)mkblock);
					fprintf(nf, "\t<key>part-num</key>\n\t<integer>0</integer>\n");
					fprintf(nf, "\t<key>version</key>\n\t<integer>6</integer>\n");
					fprintf(nf, "</dict>\n</plist>\n");
					nlen = (size_t)ftell(nf);
					nsiz = (char*)apfs_malloc(nlen + 1);
					rewind(nf);
					if(fread(nsiz, 1, nlen, nf) != nlen)
						nlen = 0;
					fclose(nf);
					fprintf(xf, "\t\t<key>nsiz</key>\n\t\t<array>\n");
					xml_dict(xf, "0x0000", NULL, (const uint8_t*)nsiz, nlen, 0, "");
					fprintf(xf, "\t\t</array>\n");
					free(nsiz);
				}
			}
			fprintf(xf, "\t\t<key>plst</key>\n\t\t<array>\n");
			xml_dict(xf, "0x0050", NULL, plst_data, sizeof(plst_data), 0, "");
			fprintf(xf, "\t\t</array>\n\t</dict>\n</dict>\n</plist>\n");
			xml_len = (size_t)ftell(xf);
			xml_buf = (char*)apfs_malloc(xml_len + 1);
			rewind(xf);
			if(fread(xml_buf, 1, xml_len, xf) != xml_len)
				ret = APFS_EIO;
			fclose(xf);
		}

		if(ret == APFS_OK) {
			uint64_t fork_len = w.pos;
			uint32_t fork_crc = w.fork_crc;
			xml_off = w.pos;
			if(fwrite(xml_buf, 1, xml_len, out) != xml_len)
				ret = APFS_EIO;
			memset(koly, 0, sizeof(koly));
			memcpy(koly, "koly", 4);
			put_be32(koly + 4, 4);
			put_be32(koly + 8, KOLY_SIZE);
			put_be32(koly + 12, 1);
			put_be64(koly + 0x10, 0);
			put_be64(koly + 0x18, 0);
			put_be64(koly + 0x20, fork_len);
			put_be32(koly + 0x38, 1);
			put_be32(koly + 0x3C, 1);
			put_be32(koly + 0x50, 2);
			put_be32(koly + 0x54, 32);
			put_be32(koly + 0x58, fork_crc);
			put_be64(koly + 0xD8, xml_off);
			put_be64(koly + 0xE0, xml_len);
			put_be32(koly + 0x160, 2);
			put_be32(koly + 0x164, 32);
			put_be32(koly + 0x168, master);
			put_be32(koly + 0x1E8, 2);
			put_be64(koly + 0x1EC, total);
			if(ret == APFS_OK && fwrite(koly, 1, KOLY_SIZE, out) != KOLY_SIZE)
				ret = APFS_EIO;
		}
		free(xml_buf);
	}

	for(i = 0; i < nregions; i++)
		free(done[i].tbl);
	free(done);
	free(regions);
	if(fflush(out) != 0 && ret == APFS_OK)
		ret = APFS_EIO;
	return ret;
}
