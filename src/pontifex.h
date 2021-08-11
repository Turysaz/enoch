#ifndef PONTIFEX__H_
#define PONTIFEX__H_
/*
 *  pontifex.h : declares the cipher system api.
 *
 *  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
 *  Copyright (C) 2021 Turysaz
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License version 2 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the
 *  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 */

/*
 *  Defines the operation modes.
 */
enum px_mode {
    PX_ENCR, /* Encrypt message */
    PX_DECR, /* Decrypt message */
    PX_STRM, /* Print key stream */
    PX_PKEY  /* Generate and print key */
};

/*
 *  This structs contains the evaluated settings
 *  defined by the CLI options.
 */
struct px_oopts {
    enum px_mode mode;
    char key[54];
    FILE *input;
    FILE *output;
    char raw; /* bool flag: raw output */
    char movjok; /* bool flag: move jokers on key generation */
    int length; /* output length */
};

/*
 * Gets an options struct initialized to defaults.
 */
struct px_oopts px_defaultopts(void);

/*
 * Reads a plain text or cipher text message from the input,
 * performs the encryption or decryption and prints the
 * result to the output.
 */
void px_ocipher(struct px_oopts *args);

/*
 * Prints the key stream to the output.
 * The number of letters is defined within the args.
 */
void px_ostream(struct px_oopts *args);

/*
 * Print the current key to output.
 */
void px_pkey(struct px_oopts *args);

/*
 * Generates the key based on a password.
 */
void px_genkey(char *password, char *key);

/*
 * Parses a key written as decimal numbers from the key string
 * to the byte array keynum.
 * Return:
 *      0 on success, errno on failure
 */
int px_kparse(char *keystr, char *keynum);
 
/*
 * Parses a key written as decimal numbers from a file
 * and saves it in the program args.
 * Return:
 *      0 on success, errno on failure
 */
int px_kread(struct px_oopts *args, char *filename);

#endif
