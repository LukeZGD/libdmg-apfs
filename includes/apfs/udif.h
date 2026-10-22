/*
 * udif.h
 * apfs-tool
 *
 * Apple UDIF disk images (.dmg): random-access reading and building.
 */

#ifndef APFS_UDIF_H
#define APFS_UDIF_H

#include <stdint.h>
#include <stdio.h>
#include "common.h"
#include "abstractfile.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UDIF_SECTOR 512

#define UDIF_ZERO 0x00000000
#define UDIF_RAW 0x00000001
#define UDIF_IGNORE 0x00000002
#define UDIF_ADC 0x80000004
#define UDIF_ZLIB 0x80000005
#define UDIF_BZIP2 0x80000006
#define UDIF_LZFSE 0x80000007
#define UDIF_LZMA 0x80000008
#define UDIF_COMMENT 0x7ffffffe
#define UDIF_TERMINATOR 0xffffffff

typedef struct {
	uint32_t type;
	uint64_t sector;              /* absolute first sector */
	uint64_t count;
	uint64_t offset;              /* absolute file offset of the compressed data */
	uint64_t length;
} udif_run_t;

typedef struct {
	char* name;
	char* cfname;
	int id;
	uint32_t attributes;
	uint64_t first_sector;
	uint64_t sector_count;
	uint32_t checksum_type;
	uint32_t checksum;
} udif_part_t;

typedef struct udif udif_t;

int udif_probe(AbstractFile* f);
udif_t* udif_open(AbstractFile* f);
void udif_close(udif_t* u);
uint64_t udif_sectors(udif_t* u);
io_func* udif_io(udif_t* u);                  /* read-only view of the whole disk; owns u */
int udif_parts(udif_t* u, udif_part_t** parts, int* count);
uint32_t udif_main_compression(udif_t* u);
const char* udif_format_name(uint32_t compression);
int udif_verify(udif_t* u, int verbose);       /* checks the CRC32 checksums */

/* Reports whether a byte range of the APFS partition is unallocated */
typedef int (*udif_free_fn)(void* ctx, uint64_t byte_offset, uint64_t length);

typedef struct {
	uint32_t compression;         /* UDIF_ZLIB, UDIF_LZFSE, UDIF_RAW, UDIF_BZIP2, UDIF_LZMA */
	int level;                    /* zlib level, default 9 */
	uint32_t chunk_sectors;       /* default 2048 */
	int imagescan;                /* add cSum and nsiz like asr imagescan */
	udif_free_fn is_free;         /* reports unallocated byte ranges, which become IGNORE runs */
	void* free_ctx;
	int nvolumes;                 /* volume names and UUIDs for nsiz */
	const char** volume_names;
	const char** volume_uuids;
	int quiet;
} udif_build_opts_t;

void udif_default_opts(udif_build_opts_t* o);
int udif_build(io_func* disk, uint64_t disk_bytes, FILE* out, const udif_build_opts_t* o);
int udif_extract(udif_t* u, int part, FILE* out, int quiet); /* part < 0: the whole disk */

/* GPT helpers: wrapping a bare container in a GPT disk like Apple's IPSW images */
io_func* udif_gpt_wrap(io_func* container, uint64_t container_bytes, uint64_t* disk_bytes);
int udif_gpt_find(io_func* disk, uint64_t disk_bytes, uint64_t* part_offset, uint64_t* part_length, int* part_index);
int udif_gpt_resize(io_func* disk, uint64_t old_bytes, uint64_t new_bytes, int part_index, uint64_t new_part_length);

uint32_t udif_mkblock_checksum(uint32_t ck, const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif
