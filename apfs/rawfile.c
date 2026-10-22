/*
 * rawfile.c
 * apfs-tool
 *
 * io_func backend for raw image files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apfs/apfs.h"
#include "apfs/image.h"
#include "apfs/platform.h"
#include "apfs/platform.h"

typedef struct {
	FILE* f;
	uint64_t size;
	int writable;
} rawfile_t;

static int raw_read(io_func* io, off_t location, size_t size, void* buffer) {
	rawfile_t* r = (rawfile_t*)io->data;
	size_t got = 0;

	if((uint64_t)location < r->size) {
		size_t want = size;
		if((uint64_t)location + want > r->size)
			want = (size_t)(r->size - (uint64_t)location);
		if(fseeko(r->f, location, SEEK_SET) != 0)
			return FALSE;
		got = fread(buffer, 1, want, r->f);
		if(got != want)
			return FALSE;
	}
	/* past the end of the file reads as zeroes, like a sparse image */
	if(got < size)
		memset((uint8_t*)buffer + got, 0, size - got);
	return TRUE;
}

static int raw_write(io_func* io, off_t location, size_t size, void* buffer) {
	rawfile_t* r = (rawfile_t*)io->data;
	if(!r->writable)
		return FALSE;
	if(fseeko(r->f, location, SEEK_SET) != 0)
		return FALSE;
	if(fwrite(buffer, 1, size, r->f) != size)
		return FALSE;
	if((uint64_t)location + size > r->size)
		r->size = (uint64_t)location + size;
	return TRUE;
}

static void raw_close(io_func* io) {
	rawfile_t* r = (rawfile_t*)io->data;
	if(r->writable)
		plat_sparse_finish(r->f);
	else
		fflush(r->f);
	fclose(r->f);
	free(r);
	free(io);
}

io_func* apfs_rawfile_open(const char* path, int writable) {
	FILE* f = fopen(path, writable ? "r+b" : "rb");
	rawfile_t* r;
	io_func* io;

	if(!f)
		return NULL;
	r = (rawfile_t*)apfs_calloc(1, sizeof(rawfile_t));
	r->f = f;
	r->writable = writable;
	fseeko(f, 0, SEEK_END);
	r->size = (uint64_t)ftello(f);
	io = (io_func*)apfs_calloc(1, sizeof(io_func));
	io->data = r;
	io->read = raw_read;
	io->write = raw_write;
	io->close = raw_close;
	return io;
}

io_func* apfs_rawfile_create(const char* path, uint64_t size) {
	FILE* f = fopen(path, "w+b");
	rawfile_t* r;
	io_func* io;

	if(!f)
		return NULL;
	if(plat_sparse_file(f, size) < 0) {
		fclose(f);
		return NULL;
	}
	r = (rawfile_t*)apfs_calloc(1, sizeof(rawfile_t));
	r->f = f;
	r->writable = 1;
	r->size = size;
	io = (io_func*)apfs_calloc(1, sizeof(io_func));
	io->data = r;
	io->read = raw_read;
	io->write = raw_write;
	io->close = raw_close;
	return io;
}

uint64_t apfs_rawfile_size(io_func* io) {
	return ((rawfile_t*)io->data)->size;
}

/* Lets other streams of the file read what was written */
int apfs_rawfile_flush(io_func* io) {
	return fflush(((rawfile_t*)io->data)->f) == 0 ? APFS_OK : APFS_EIO;
}

int apfs_rawfile_truncate(io_func* io, uint64_t size) {
	rawfile_t* r = (rawfile_t*)io->data;
	if(size > r->size) {
		if(plat_sparse_file(r->f, size) < 0)
			return APFS_EIO;
		r->size = size;
		return APFS_OK;
	}
	/* shrinking is not needed by any operation */
	return size == r->size ? APFS_OK : APFS_EUNSUPP;
}
