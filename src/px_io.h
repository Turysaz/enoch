#ifndef PX_IO__H_
#define PX_IO__H_

/*
 *  px_io.h : Definition of the I/O functions like parsing keys
 *            or messages from files, or writing ciphertext to files.
 *
 *  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
 *  Copyright (C) 2021 Turysaz
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include "./px_common.h"

/* FLAGS */
#define PXO_RAW 1

/**
 * Print the cipher text as groups of 5 characters.
 *
 * \para ctext  The ciphertext, zero-terminated.
 * \para stream Pointer to the output file.
 * \para flags   Output options.
 */
void px_prcipher(
    const char * const ctext,
    FILE *stream,
    const unsigned int flags);

/**
 * Print a key to a file.
 *
 * \para key    Pointer to the key, as 54-element char array.
 * \para stream Pointer to the output file.
 * \para flags   Output options.
 */
void px_prkey(const card * const key, FILE *stream, const unsigned int flags);

/**
 * Read a cipher text message.
 *
 * \para ciphert  Cipher text (needs to be 0-terminated!)
 * \para buf      Pointer to buffer to write the cipher text to.
 *
 * \returns The length of the cipher text, 0-terminator included,
 *         if successfull. -1 on failure.
 */
int px_rdcipher(const char *ciphert, char **buf);

/**
 * Read a key from text.
 *
 * \para keystr Pointer to key text representation.
 * \para key    Pointer to 54-element array to write the key to.
 *
 * \returns 0 on success, -1 on failure.
 */
int px_rdkey(const char *keystr, card *key);

#endif
