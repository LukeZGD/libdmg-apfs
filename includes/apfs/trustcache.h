/*
 * trustcache.h
 * apfs-tool
 *
 * Trust caches: sorted lists of code directory hashes (CDHashes) that iOS
 * and macOS run as platform code. Restore IPSWs carry one for each system
 * and ramdisk image (Firmware/<image>.dmg.trustcache, IM4P type trst or rtsc).
 */

#ifndef APFS_TRUSTCACHE_H
#define APFS_TRUSTCACHE_H

#include <stdio.h>
#include "apfs/apfs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APFS_CDHASH_LEN 20
#define APFS_TC_MAX_HASHES 32         /* per file */

/* code directory hash types */
#define APFS_CS_SHA1 1
#define APFS_CS_SHA256 2
#define APFS_CS_SHA256_TRUNCATED 3
#define APFS_CS_SHA384 4

typedef struct {
	uint8_t cdhash[APFS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;                /* 1: amfid, 2: ANE model */
	uint8_t category;             /* launch constraint category (version 2) */
} apfs_tc_entry_t;

typedef struct {
	apfs_tc_entry_t* entries;
	size_t count;
	size_t cap;
	size_t base;                  /* entries[0..base) are sorted; scans keep them as they are */
} apfs_tc_t;

/* Reads exactly len bytes at off */
typedef int (*apfs_tc_read_t)(void* ctx, uint64_t off, void* buf, size_t len);

/* The CDHashes of a file: one per architecture of a Mach-O file, one for a
 * dyld shared cache and one per code directory of a standalone signature.
 * Returns how many were stored in out (at most max), 0 for files that hold
 * no code, APFS_ENOENT for code without a signature, APFS_EUNSUPP for
 * SHA-384 code directories or APFS_ECORRUPT. */
int apfs_tc_hash_file(apfs_tc_read_t read, void* ctx, uint64_t size, apfs_tc_entry_t* out, size_t max);

/* Adds the CDHashes of the files at or below path, listing them on list
 * unless it is NULL. Unsigned or unreadable signatures are skipped with a
 * warning. */
int apfs_tc_scan(apfs_vol_t* vol, const char* path, apfs_tc_t* tc, FILE* list);

/* A version 1 or 2 trust cache, sorted by CDHash without duplicates. Without
 * a uuid, one is derived from the contents. */
uint8_t* apfs_tc_build(apfs_tc_t* tc, int version, const uint8_t* uuid, size_t* len);

/* Fills an empty trust cache set from serialized data */
int apfs_tc_parse(const uint8_t* data, size_t len, apfs_tc_t* tc, int* version, uint8_t uuid[16]);

/* Trust cache files, raw or IM4P; saving makes an IM4P when im4p_type is set */
int apfs_tc_load(const char* path, apfs_tc_t* tc, int* version);
int apfs_tc_save(apfs_tc_t* tc, int version, const char* im4p_type, const char* path);
void apfs_tc_free(apfs_tc_t* tc);

#ifdef __cplusplus
}
#endif

#endif
