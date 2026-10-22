/*
 * platform.h
 * apfs-tool
 *
 * Host file system access for importing and exporting files, isolated so
 * the rest of the code stays portable between POSIX systems and Windows.
 */

#ifndef APFS_PLATFORM_H
#define APFS_PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct {
	uint16_t mode;                /* type and permission bits, APFS_S_* encoding */
	uint32_t uid;
	uint32_t gid;
	uint32_t rdev;
	uint32_t flags;               /* BSD file flags where the host has them */
	uint64_t size;
	uint64_t atime;               /* nanoseconds since the epoch */
	uint64_t mtime;
	uint64_t ctime;
	uint64_t btime;
	uint64_t ino;
	uint64_t dev;
	uint32_t nlink;
} plat_stat_t;

int plat_lstat(const char* path, plat_stat_t* st);
int plat_readlink(const char* path, char** target);
/* Returns the entries of a directory, sorted, without "." and ".." */
int plat_list_dir(const char* path, char*** names, size_t* count);
void plat_free_list(char** names, size_t count);
int plat_mkdir(const char* path, uint16_t mode);
int plat_symlink(const char* target, const char* path);
int plat_link(const char* existing, const char* path);
int plat_mknod(const char* path, uint16_t mode, uint32_t rdev);
int plat_chmod(const char* path, uint16_t mode);
int plat_chown(const char* path, uint32_t uid, uint32_t gid);
int plat_set_times(const char* path, uint64_t atime, uint64_t mtime);
int plat_set_flags(const char* path, uint32_t flags);
int plat_is_root(void);

/* Extended attributes of host files; return a negative value when unsupported */
int plat_xattr_list(const char* path, char*** names, size_t* count);
int plat_xattr_get(const char* path, const char* name, uint8_t** data, size_t* size);
int plat_xattr_set(const char* path, const char* name, const uint8_t* data, size_t size);

char* plat_join(const char* dir, const char* name);
int plat_exists(const char* path);
int plat_remove(const char* path);
int plat_same_file(const char* a, const char* b);
char* plat_temp_path(const char* hint);
int plat_sparse_file(FILE* f, uint64_t size);
/* On macOS, discard zero blocks that short-file write clustering may have
 * allocated despite the file having been created sparse. */
int plat_sparse_finish(FILE* f);
int plat_write_sparse(FILE* f, uint64_t off, const void* data, size_t len);

#endif
