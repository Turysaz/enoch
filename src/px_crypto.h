#ifndef PX_CRYPTO__H_
#define PX_CRYPTO__H_

/*
 *  px_crypto.h : declares the cryptosystem api.
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

#include "./px_common.h"

/**
 * Options for applying the pontifex algorithm.
 */
struct px_opts {
    /**
     * To increase the security of the algorithm, the number
     * of rounds to perform before taking a keystream letter
     * can be increased.
     */
    unsigned int rounds;
};

/**
 * Encrypts a message using the pontifex algorithm.
 *
 * \param key   Pointer to the 54-element long key.
 * \param msg   Pointer to the 0-terminated  message that shall be encrypted.
 * \param nmsg  The length of msg (0-terminator NOT included).
 * \param buf   out: The buffer that the ciphertext shall be written to.
 * \param opts  Options for the crypto algorithm.
 *
 * \returns     The length of the generated ciphertext in buf,
 *              0-terminator included.
 */
int px_encrypt(
    const card *key,
    const char *msg,
    const int nmsg,
    char **buf,
    const struct px_opts *opts);

/**
 * Decrypts a message using the pontifex algorithm.
 *
 * \param key   Pointer to the 54-element long key.
 * \param msg   Pointer to the 0-terminated ciphertext that shall be decrypted.
 * \param nmsg  The length of msg (0-terminator not included).
 * \param buf   out: The buffer that the plain text shall be written to.
 * \param opts  Options for the crypto algorithm.
 *
 * \returns     The length of the decrypted plaintext in buf.
 *              0-terminator included.
 */
int px_decrypt(
    const card *key,
    const char *msg,
    const int nmsg,
    char **buf,
    const struct px_opts *opts);

/**
 * Generates letters of the key stream for the pontifex algorithm.
 *
 * \param key   Pointer to the 54-element long key.
 * \param count Amount of key stream letters to generate.
 * \param buf   out: The buffer that the plain text shall be written to.
 * \param opts  Options for the crypto algorithm.
 *
 * \returns     0 on success, -1 on failure.
 */
int px_stream(
    const card *key,
    const int count,
    char **buf,
    const struct px_opts *opts);

/**
 * Generates a key for the pontifex key stream algorithm based on a
 * password.
 *
 * \param password  Pointer to a zero-terminated password string.
 * \param mvjokers  Boolean flag that defines if the jokers shall be moved.
 * \param key       out: Pointer to the 54-element byte array that is the
 *                  generated key.
 * \returns         0 on success, -1 on failure.
 */
int px_keygen(
    const char *password,
    const int mvjokers,
    card * const key);

#endif

