/*
 * image.h
 * apfs-tool
 *
 * Opening the files that hold APFS containers: raw images (optionally
 * partitioned with GPT), UDIF disk images (.dmg) and IMG4 payloads (.im4p).
 */

#ifndef APFS_IMAGE_H
#define APFS_IMAGE_H

#include "apfs/apfs.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	APFS_IMG_RAW = 0,
	APFS_IMG_DMG = 1,
	APFS_IMG_IM4P = 2
};

typedef struct apfs_image {
	char* path;
	int writable;
	int format;
	io_func* io;                  /* whole device */
	uint64_t base;                /* byte offset of the APFS container */
	uint64_t length;              /* byte length of the partition, 0 if unknown */
	apfs_nx_t* nx;
	char* out_path;               /* where the modified image is written */
	char* work_path;              /* raw working copy for DMG/IM4P images */
	int dirty;
	void* format_state;           /* format-specific data needed to rewrap */
} apfs_image_t;

io_func* apfs_rawfile_open(const char* path, int writable);
io_func* apfs_rawfile_create(const char* path, uint64_t size);
uint64_t apfs_rawfile_size(io_func* io);
int apfs_rawfile_truncate(io_func* io, uint64_t size);
int apfs_rawfile_flush(io_func* io);

/* Locates an APFS container inside a raw device. Returns its byte offset and,
 * when partitioned, the partition length. */
int apfs_find_container(io_func* io, uint64_t dev_size, uint64_t* base, uint64_t* length);

extern const char* apfs_image_tmpdir;
/* The key (hex or base64) or passphrase of encrypted images and archives */
extern const char* apfs_image_key;
extern const char* apfs_image_passphrase;

int apfs_image_open(const char* path, int writable, apfs_image_t** out);
int apfs_image_open_ex(const char* path, int writable, const char* out_path, apfs_image_t** out);
int apfs_image_close(apfs_image_t* img, int save);
int apfs_image_grow(apfs_image_t* img, uint64_t new_size);
int apfs_image_export(apfs_image_t* img, const char* fmt, const char* out_path, int argc, char** argv);
int apfs_image_range_free(void* ctx, uint64_t off, uint64_t len);
io_func* apfs_subrange_io(io_func* inner, uint64_t off, uint64_t len);

/* Small IMG4 payloads such as trust caches, in memory. Loading returns the
 * payload of an IM4P or IMG4 file, or the whole of any other file. */
int apfs_im4p_load(const char* path, uint8_t** data, size_t* len);
int apfs_im4p_save(const char* type, const char* desc, const void* data, size_t len, const char* path);

#ifdef __cplusplus
}
#endif

#endif
