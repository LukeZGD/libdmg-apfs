/*
 * debug.h
 * apfs-tool
 */

#ifndef APFS_DEBUG_H
#define APFS_DEBUG_H

#include <stdio.h>
#include "apfs/apfs.h"

void apfs_dump_container(apfs_nx_t* nx, FILE* f);
void apfs_dump_volume(apfs_vol_t* vol, FILE* f);
int apfs_dump_tree(apfs_btree_t* bt, const char* name, int records, FILE* f);
int apfs_dump_free_queues(apfs_nx_t* nx, int records, FILE* f);

#endif
