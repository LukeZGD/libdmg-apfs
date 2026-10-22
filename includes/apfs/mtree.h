/*
 * mtree.h
 * apfs-tool
 *
 * The canonical metadata of system volumes, which IPSWs carry as
 * Firmware/<system>.dmg.mtree: a BSD mtree specification of the volume.
 */

#ifndef APFS_MTREE_H
#define APFS_MTREE_H

#include "apfs/apfs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The specification as macOS "mtree -c -S -k type,inode,siblingid,nxattr,
 * xattrsdigest" prints it, with time (in seconds) on the root directory and
 * /.file, as in Apple's files. Returns a NUL-terminated string. */
int apfs_mtree_spec(apfs_vol_t* vol, uint64_t time, char** out, size_t* len);

/* The IPSW form of a specification: an Apple Archive holding mtree.txt,
 * compressed with LZFSE in "pbze" blocks, as "aa archive -a lzfse" writes */
uint8_t* apfs_mtree_archive(const char* spec, size_t len, uint64_t time, size_t* out_len);

/* Writes a specification raw, or archived in an IMG4 payload of im4p_type
 * (IPSWs use msys) */
int apfs_mtree_save(const char* spec, size_t len, uint64_t time, const char* im4p_type, const char* path);

#ifdef __cplusplus
}
#endif

#endif
