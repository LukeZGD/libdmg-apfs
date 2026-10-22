/*
 * dmg-tool.c
 * apfs-tool
 *
 * dmg: converts between UDIF disk images (.dmg) and raw disk images, with
 * the extract and build commands of libdmg-hfsplus' dmg tool. It works with
 * any file system; APFS images can also be converted by apfs-tool itself,
 * which leaves out unallocated blocks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"
#include "apfs/udif.h"
#include "apfs/image.h"

static udif_t* open_dmg(const char* path) {
	FILE* f = fopen(path, "rb");
	AbstractFile* af;
	udif_t* u;

	if(!f) {
		fprintf(stderr, "error: cannot open %s\n", path);
		return NULL;
	}
	af = createAbstractFileFromFile(f);
	if(!udif_probe(af) || !(u = udif_open(af))) {
		fprintf(stderr, "error: %s is not a UDIF disk image\n", path);
		af->close(af);
		return NULL;
	}
	return u;
}

static int cmd_extract(int argc, char** argv) {
	udif_t* u = open_dmg(argv[2]);
	FILE* out;
	int ret, want = -1;

	if(!u)
		return 1;
	out = fopen(argv[3], "w+b");
	if(!out) {
		fprintf(stderr, "error: cannot create %s\n", argv[3]);
		udif_close(u);
		return 1;
	}
	if(argc > 4) {
		/* a single partition, by number or by name */
		udif_part_t* parts;
		int nparts, i;
		char* end;
		long n = strtol(argv[4], &end, 10);

		udif_parts(u, &parts, &nparts);
		for(i = 0; i < nparts; i++)
			if((!*end && parts[i].id == n) || (parts[i].name && strstr(parts[i].name, argv[4])))
				want = i;
		if(want < 0) {
			fprintf(stderr, "error: no partition %s\n", argv[4]);
			udif_close(u);
			fclose(out);
			return 1;
		}
	}
	ret = udif_extract(u, want, out, 0);
	udif_close(u);
	if(fclose(out) != 0 && ret == APFS_OK)
		ret = APFS_EIO;
	if(ret < 0) {
		fprintf(stderr, "error: cannot extract %s: %s\n", argv[2], apfs_strerror(ret));
		return 1;
	}
	return 0;
}

static int cmd_build(int argc, char** argv) {
	udif_build_opts_t o;
	io_func* io;
	FILE* out;
	uint64_t size;
	int i, ret;

	udif_default_opts(&o);
	for(i = 4; i < argc; i++) {
		if(!strcmp(argv[i], "-c") && i + 1 < argc) {
			const char* c = argv[++i];
			if(!strcmp(c, "lzfse"))
				o.compression = UDIF_LZFSE;
			else if(!strcmp(c, "zlib"))
				o.compression = UDIF_ZLIB;
			else if(!strcmp(c, "raw"))
				o.compression = UDIF_RAW;
			else {
				fprintf(stderr, "error: unknown compression %s\n", c);
				return 1;
			}
		} else {
			fprintf(stderr, "error: unknown option %s\n", argv[i]);
			return 1;
		}
	}
	io = apfs_rawfile_open(argv[2], 0);
	if(!io) {
		fprintf(stderr, "error: cannot open %s\n", argv[2]);
		return 1;
	}
	size = apfs_rawfile_size(io);
	out = fopen(argv[3], "wb");
	if(!out) {
		fprintf(stderr, "error: cannot create %s\n", argv[3]);
		CLOSE(io);
		return 1;
	}
	ret = udif_build(io, size, out, &o);
	CLOSE(io);
	if(fclose(out) != 0 && ret == APFS_OK)
		ret = APFS_EIO;
	if(ret < 0) {
		fprintf(stderr, "error: cannot build %s: %s\n", argv[3], apfs_strerror(ret));
		return 1;
	}
	return 0;
}

static int cmd_info(int argc, char** argv) {
	udif_t* u = open_dmg(argv[2]);
	udif_part_t* parts;
	int nparts, i;

	(void)argc;
	if(!u)
		return 1;
	udif_parts(u, &parts, &nparts);
	printf("format:  %s\n", udif_format_name(udif_main_compression(u)));
	printf("size:    %llu bytes (%llu sectors)\n", (unsigned long long)(udif_sectors(u) * UDIF_SECTOR),
		(unsigned long long)udif_sectors(u));
	for(i = 0; i < nparts; i++)
		printf("  %3d  %12llu + %-12llu  %s\n", parts[i].id, (unsigned long long)parts[i].first_sector,
			(unsigned long long)parts[i].sector_count, parts[i].name ? parts[i].name : "");
	udif_close(u);
	return 0;
}

static int cmd_verify(int argc, char** argv) {
	udif_t* u = open_dmg(argv[2]);
	int ret;
	(void)argc;
	if(!u)
		return 1;
	ret = udif_verify(u, 1);
	udif_close(u);
	printf("%s\n", ret == APFS_OK ? "The checksums are valid." : "The image is damaged.");
	return ret < 0;
}

static void usage(const char* prog) {
	printf("usage: %s extract <in.dmg> <out.img> [partition]   write the disk (or one partition) raw\n", prog);
	printf("       %s build <in.img> <out.dmg> [-c lzfse|zlib|raw]   make a UDIF image (default zlib)\n", prog);
	printf("       %s info <in.dmg>                             list the partitions\n", prog);
	printf("       %s verify <in.dmg>                           check the data checksums\n", prog);
	printf("(\"iso\" and \"dmg\" are accepted as in libdmg-hfsplus, for extract and build)\n");
}

int main(int argc, char** argv) {
	/* "iso" and "dmg" are libdmg-hfsplus' names for whole-disk conversions */
	if(argc >= 4 && (!strcmp(argv[1], "extract") || (argc == 4 && !strcmp(argv[1], "iso"))))
		return cmd_extract(argc, argv);
	if(argc >= 4 && (!strcmp(argv[1], "build") || !strcmp(argv[1], "dmg")))
		return cmd_build(argc, argv);
	if(argc == 3 && !strcmp(argv[1], "info"))
		return cmd_info(argc, argv);
	if(argc == 3 && !strcmp(argv[1], "verify"))
		return cmd_verify(argc, argv);
	usage(argv[0]);
	return argc < 2 ? 0 : 1;
}
