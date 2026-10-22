/*
 * encrypted.h
 * apfs-tool
 *
 * Encrypted disk images: hdiutil's encrypted images (encrcdsa) and Apple
 * Encrypted Archives (AEA1), opened as read-only files that decrypt what
 * they hold on the fly.
 */

#ifndef APFS_ENCRYPTED_H
#define APFS_ENCRYPTED_H

#include <stdint.h>
#include <stdio.h>
#include "abstractfile.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Decodes a key given as hex digits or base64 (optionally prefixed with
 * "hex:" or "base64:", as Apple's aea tool takes them) */
int apfs_parse_key(const char* s, uint8_t** key, size_t* len);

/* encrcdsa images, version 2. The key is the AES key followed by the
 * HMAC-SHA1 key, as libdmg-hfsplus' -k takes it; a passphrase unwraps
 * them from the image instead. */
typedef struct encrcdsa_info encrcdsa_info_t;

int encrcdsa_probe(AbstractFile* f);
/* Takes over f. info, if not NULL, receives what encrcdsa_save needs. */
AbstractFile* encrcdsa_open(AbstractFile* f, const uint8_t* key, size_t key_len, const char* passphrase, encrcdsa_info_t** info);
/* Writes len bytes of plain to out as an image with the header, and so the
 * passphrase, of the opened one */
int encrcdsa_save(const encrcdsa_info_t* info, FILE* plain, uint64_t len, FILE* out);
/* The AES key bits and the key in the form -k takes, as hex */
int encrcdsa_key_bits(const encrcdsa_info_t* info);
void encrcdsa_key_hex(const encrcdsa_info_t* info, char* out);
void encrcdsa_info_free(encrcdsa_info_t* info);

/* Apple Encrypted Archives with profile 1 (a symmetric key, no
 * signature), which IPSWs use for their file systems */
int aea_probe(AbstractFile* f);
AbstractFile* aea_open(AbstractFile* f, const uint8_t* key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif
