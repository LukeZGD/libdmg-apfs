/*
 * mtree.c
 * apfs-tool
 *
 * Writes the canonical metadata of system volumes. Apple's files are what
 * macOS "mtree -c -S -k type,inode,siblingid,nxattr,xattrsdigest" prints for
 * the volume, plus the time of the build on the root directory and on
 * /.file. The layout follows BSD mtree: names padded to 15 columns, lines
 * wrapped before 80, other entries before subdirectories, each group in
 * strcmp order.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "apfs/apfs.h"
#include "apfs/mtree.h"
#include "apfs/image.h"
#include "apfs/platform.h"
#include "lzfse.h"

#define INDENTNAMELEN 15
#define MAXLINELEN 80

/* entry() flags: Apple's specifications give the root directory and /.file a time */
#define TIMES_ROOT 1
#define TIMES_DOTFILE 2

typedef struct {
	char* p;
	size_t len;
	size_t cap;
} buf_t;

typedef struct {
	apfs_vol_t* vol;
	uint64_t time;
	buf_t b;
} mtree_t;

static void buf_add(buf_t* b, const void* s, size_t n) {
	if(b->len + n + 1 > b->cap) {
		b->cap = (b->len + n + 1) * 2;
		b->p = (char*)apfs_realloc(b->p, b->cap);
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = 0;
}

static void buf_puts(buf_t* b, const char* s) {
	buf_add(b, s, strlen(s));
}

static void buf_printf(buf_t* b, const char* fmt, ...) {
	char s[512];
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = vsnprintf(s, sizeof(s), fmt, ap);
	va_end(ap);
	if(n > 0)
		buf_add(b, s, (size_t)n < sizeof(s) ? (size_t)n : sizeof(s) - 1);
}

/* Names as vis(3) encodes them with VIS_WHITE | VIS_OCTAL | VIS_GLOB */
static int put_name(buf_t* b, const char* name) {
	const unsigned char* s;
	int n = 0;
	for(s = (const unsigned char*)name; *s; s++) {
		if(*s <= ' ' || *s >= 0x7f || strchr("#*?[\\", *s)) {
			char e[5];
			snprintf(e, sizeof(e), "\\%03o", *s);
			buf_add(b, e, 4);
			n += 4;
		} else {
			buf_add(b, s, 1);
			n++;
		}
	}
	return n;
}

static void keyword(buf_t* b, int* offset, const char* fmt, ...) {
	char s[64];
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = vsnprintf(s, sizeof(s), fmt, ap);
	va_end(ap);
	if(*offset + n > MAXLINELEN - 3) {
		buf_printf(b, " \\\n%*s", INDENTNAMELEN, "");
		*offset = INDENTNAMELEN;
	}
	buf_add(b, " ", 1);
	buf_add(b, s, (size_t)n);
	*offset += n + 2;
}

static const char* type_name(unsigned dt) {
	switch(dt) {
		case APFS_DT_DIR: return "dir";
		case APFS_DT_LNK: return "link";
		case APFS_DT_CHR: return "char";
		case APFS_DT_BLK: return "block";
		case APFS_DT_FIFO: return "fifo";
		case APFS_DT_SOCK: return "socket";
		default: return NULL;     /* files: the /set default */
	}
}

/* The extended attributes that listxattr shows with XATTR_SHOWCOMPRESSION
 * (it hides the ones the file system owns, such as symlink targets), and the
 * object id of the data stream holding the resource fork, which "mtree -S"
 * uses as the digest (0 when the fork is absent or stored inline) */
static int xattr_info(apfs_vol_t* vol, uint64_t ino, unsigned* count, uint64_t* stream) {
	char** names;
	size_t n, i;
	int ret = apfs_xattr_list(vol, ino, &names, &n);

	*count = 0;
	*stream = 0;
	if(ret < 0)
		return ret;
	for(i = 0; ret == APFS_OK && i < n; i++) {
		uint16_t flags, xlen;
		uint8_t* x;
		ret = apfs_xattr_raw(vol, ino, names[i], &flags, &x, &xlen);
		if(ret < 0)
			break;
		if(!(flags & XATTR_FILE_SYSTEM_OWNED)) {
			(*count)++;
			if((flags & XATTR_DATA_STREAM) && xlen >= 8 && !strcmp(names[i], RESOURCEFORK_EA_NAME))
				*stream = apfs_get64(x);
		}
		free(x);
	}
	apfs_names_free(names, n);
	return ret;
}

static int entry(mtree_t* m, const char* name, uint64_t ino, uint64_t sibling, unsigned dt, int times) {
	const char* type = type_name(dt);
	unsigned nxattr;
	uint64_t stream;
	int offset, ret;

	if((ret = xattr_info(m->vol, ino, &nxattr, &stream)) < 0)
		return ret;
	offset = dt == APFS_DT_DIR ? 0 : 4;
	buf_add(&m->b, "    ", (size_t)offset);
	offset += put_name(&m->b, name);
	if(offset > INDENTNAMELEN) {
		offset = MAXLINELEN;
	} else {
		buf_printf(&m->b, "%*s", INDENTNAMELEN - offset, "");
		offset = INDENTNAMELEN;
	}
	if(type)
		keyword(&m->b, &offset, "type=%s", type);
	if(times & TIMES_ROOT) {
		keyword(&m->b, &offset, "time=%llu.000000000", (unsigned long long)m->time);
		keyword(&m->b, &offset, "btime=%llu.000000000", (unsigned long long)m->time);
		keyword(&m->b, &offset, "ctime=%llu.000000000", (unsigned long long)m->time);
		keyword(&m->b, &offset, "ptime=%llu.000000000", (unsigned long long)m->time);
	}
	if(times & TIMES_DOTFILE)
		keyword(&m->b, &offset, "atime=%llu.000000000", (unsigned long long)m->time);
	if(nxattr)
		keyword(&m->b, &offset, "xattrsdigest=authapfs.%llu", (unsigned long long)stream);
	keyword(&m->b, &offset, "inode=%llu", (unsigned long long)ino);
	keyword(&m->b, &offset, "siblingid=%llu", (unsigned long long)sibling);
	keyword(&m->b, &offset, "nxattr=%u", nxattr);
	buf_add(&m->b, "\n", 1);
	return APFS_OK;
}

static int cmp_dirent(const void* a, const void* b) {
	return strcmp(((const apfs_dirent_t*)a)->name, ((const apfs_dirent_t*)b)->name);
}

/* A directory: a comment with its path, its own line, its other entries, its
 * subdirectories, and the line that goes back up */
static int section(mtree_t* m, uint64_t ino, const char* name, const char* path, uint64_t sibling, int root) {
	apfs_dirent_t* ents;
	size_t n, i;
	int ret;

	buf_puts(&m->b, "\n# ");
	buf_puts(&m->b, path);
	buf_puts(&m->b, "\n");
	if(root)
		buf_puts(&m->b, "/set type=file xattrsdigest=none.0\n");
	if((ret = entry(m, name, ino, sibling, APFS_DT_DIR, root ? TIMES_ROOT : 0)) < 0)
		return ret;
	if((ret = apfs_dir_list(m->vol, ino, &ents, &n)) < 0)
		return ret;
	if(n)
		qsort(ents, n, sizeof(*ents), cmp_dirent);
	for(i = 0; ret == APFS_OK && i < n; i++) {
		unsigned dt = ents[i].flags & DREC_TYPE_MASK;
		if(dt != APFS_DT_DIR)
			ret = entry(m, ents[i].name, ents[i].ino, ents[i].sibling_id, dt,
				root && dt == APFS_DT_REG && !strcmp(ents[i].name, ".file") ? TIMES_DOTFILE : 0);
	}
	for(i = 0; ret == APFS_OK && i < n; i++) {
		if((ents[i].flags & DREC_TYPE_MASK) == APFS_DT_DIR) {
			char* sub = plat_join(path, ents[i].name);
			ret = section(m, ents[i].ino, ents[i].name, sub, ents[i].sibling_id, 0);
			free(sub);
		}
	}
	apfs_dirents_free(ents, n);
	if(ret < 0)
		return ret;
	if(!root) {
		buf_puts(&m->b, "# ");
		buf_puts(&m->b, path);
		buf_puts(&m->b, "\n");
	}
	buf_puts(&m->b, "..\n\n");
	return APFS_OK;
}

int apfs_mtree_spec(apfs_vol_t* vol, uint64_t time, char** out, size_t* len) {
	mtree_t m;
	char date[64] = "";
	time_t t = (time_t)time;
	struct tm* tm = gmtime(&t);
	int ret;

	memset(&m, 0, sizeof(m));
	m.vol = vol;
	m.time = time;
	if(tm)
		strftime(date, sizeof(date), "%a %b %e %H:%M:%S %Y", tm);
	buf_printf(&m.b, "#\t   user: root\n#\tmachine: apfs-tool\n#\t   tree: /Volumes/%.256s\n#\t   date: %s\n",
		(const char*)vol->sb->apfs_volname, date);
	ret = section(&m, ROOT_DIR_INO_NUM, ".", ".", 0, 1);
	if(ret < 0) {
		free(m.b.p);
		return ret;
	}
	*out = m.b.p;
	*len = m.b.len;
	return APFS_OK;
}

/* Apple Archive */

#define PBZE_BLOCK (4U << 20)

static void put_be64(buf_t* b, uint64_t v) {
	uint8_t x[8];
	int i;
	for(i = 0; i < 8; i++)
		x[i] = (uint8_t)(v >> (56 - 8 * i));
	buf_add(b, x, 8);
}

/* An entry header with the fields of Apple's files: type, path, owner root
 * and group admin, mode, flags, creation and modification times, and for
 * files the size of the data that follows */
static void aa_header(buf_t* b, char type, const char* path, uint16_t mode, uint64_t time, uint32_t size) {
	uint8_t h[128];
	size_t n = 6, plen = strlen(path);

	memcpy(h, "AA01", 4);
	memcpy(h + n, "TYP1", 4); h[n + 4] = (uint8_t)type; n += 5;
	memcpy(h + n, "PATP", 4); apfs_put16(h + n + 4, (uint16_t)plen); memcpy(h + n + 6, path, plen); n += 6 + plen;
	memcpy(h + n, "UID1", 4); h[n + 4] = 0; n += 5;
	memcpy(h + n, "GID1", 4); h[n + 4] = 80; n += 5;
	memcpy(h + n, "MOD2", 4); apfs_put16(h + n + 4, mode); n += 6;
	memcpy(h + n, "FLG1", 4); h[n + 4] = 0; n += 5;
	memcpy(h + n, "CTMT", 4); apfs_put64(h + n + 4, time); apfs_put32(h + n + 12, 0); n += 16;
	memcpy(h + n, "MTMT", 4); apfs_put64(h + n + 4, time); apfs_put32(h + n + 12, 0); n += 16;
	if(type == 'F') {
		memcpy(h + n, "DATB", 4); apfs_put32(h + n + 4, size); n += 8;
	}
	apfs_put16(h + 4, (uint16_t)n);
	buf_add(b, h, n);
}

uint8_t* apfs_mtree_archive(const char* spec, size_t len, uint64_t time, size_t* out_len) {
	buf_t aa, out;
	uint8_t* block = (uint8_t*)apfs_malloc(PBZE_BLOCK);
	void* scratch = apfs_malloc(lzfse_encode_scratch_size() + 1);
	size_t off;

	memset(&aa, 0, sizeof(aa));
	memset(&out, 0, sizeof(out));
	aa_header(&aa, 'D', "", 0700, time, 0);
	aa_header(&aa, 'F', "mtree.txt", 0644, time, (uint32_t)len);
	buf_add(&aa, spec, len);
	/* "pbze", the block size, then for each block its size, its stored size and
	 * its data, LZFSE-compressed unless that does not make it smaller */
	buf_add(&out, "pbze", 4);
	put_be64(&out, PBZE_BLOCK);
	for(off = 0; off < aa.len; off += PBZE_BLOCK) {
		size_t n = aa.len - off < PBZE_BLOCK ? aa.len - off : PBZE_BLOCK;
		size_t c = lzfse_encode_buffer(block, n, (const uint8_t*)aa.p + off, n, scratch);
		put_be64(&out, n);
		if(c && c < n) {
			put_be64(&out, c);
			buf_add(&out, block, c);
		} else {
			put_be64(&out, n);
			buf_add(&out, aa.p + off, n);
		}
	}
	free(scratch);
	free(block);
	free(aa.p);
	*out_len = out.len;
	return (uint8_t*)out.p;
}

int apfs_mtree_save(const char* spec, size_t len, uint64_t time, const char* im4p_type, const char* path) {
	int ret = APFS_EIO;

	if(im4p_type) {
		size_t alen;
		uint8_t* a = apfs_mtree_archive(spec, len, time, &alen);
		/* the description of IPSW mtree payloads */
		ret = apfs_im4p_save(im4p_type, "0", a, alen, path);
		free(a);
	} else {
		FILE* f = fopen(path, "wb");
		if(f) {
			ret = fwrite(spec, 1, len, f) == len ? APFS_OK : APFS_EIO;
			if(fclose(f) != 0)
				ret = APFS_EIO;
		}
	}
	return ret;
}
