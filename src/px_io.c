/*
 *  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
 *  Copyright (C) 2021 Turysaz
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "./px_io.h"
#include "./logging.h"

/*
 * =============  Header API implementation ================
 */

/**
 * Print the cipher text as groups of 5 characters.
 * See header.
 */
void px_prcipher(const char *ctext, FILE *stream, const unsigned int flags) {
    int raw = 0; /* bool flag */
    char c;
    int i = 0;

    raw = (flags & PXO_RAW);
    if (!raw) fprintf(stream, "\n\n-----BEGIN PONTIFEX MESSAGE-----\n\n");

    while ((c = ctext[i++])) {
        fputc(c, stream);

        /* Grouping and linebreaks */
        if (i % 40 == 0 ) {
            fputc('\n', stream);
        } else if (i % 5 == 0) {
            fputc(' ', stream);
        }
    }

    if (i % 40 != 1) fputc('\n', stream);

    if (!raw) fprintf(stream, "\n-----END PONTIFEX MESSAGE-----\n\n");
}

/**
 * Print a key to a file.
 * See header.
 */
void px_prkey(const char *key, FILE *stream, const unsigned int flags) {
    int i;

    for (i = 0; i < 54; i++) {
        /* TODO: validate? */
        fprintf(stream, "%02i", key[i]);
    }
    fputc('\n', stream);
}

/**
 * Read a cipher text message.
 * See header.
 */
int px_rdcipher(char *ciphert, char **buf) {
    LOG_ERR(("NOT IMPLEMENTED\n"));
    return -1;
}

/**
 * Read a key from text.
 * See header.
 */
int px_rdkey(char *keystr, char *key) {
    int i, k;
    char numbuf[3] = { 0, 0, 0 }, /* 2-chars string for next card number */
         used[54]; /* stores which card was used how many times */
    char c;

    memset(used, 0, sizeof(used)); /* reset count field */

    while ((c = keystr[0]) == ' ' || c == 0x0a || c == 0x0d) {
        keystr += sizeof(char); /* move start of string to right */
        LOG_DBG(("Ignoring whitespace before key...\n"));
    }

    for (i = 0; i < 54; i++) {
        numbuf[0] = keystr[i*2];
        if (numbuf[0] == '\0') {
            LOG_ERR(("Key at least one character too short!\n"));
            return -1;
        }

        numbuf[1] = keystr[i*2+1];
        if (!isdigit(numbuf[0]) || !isdigit(numbuf[1])) {
            LOG_ERR((
                "Key not numeric or too short! "
                "Bad symbol at card #%i.\n",
                i + 1));
            return -1;
        }

        k = atoi(numbuf);

        /* Validation */
        if (k < 1 || k > 54) {
            LOG_ERR (("Invalid card number: %i\n", k));
            return -1;
        }

        if (used[k-1]++ != 0) {
            LOG_WRN(("The card %i occurs more than once!\n", k));
        }

        key[i] = k;
    }

    i = 54 * 2; /* Set one byte past expected key. */
    while ((c = keystr[i++]) == ' ' || c == 0x0a || c == 0x0d) {
        LOG_DBG(("Ignoring whitespace after key...\n"));
    }

    if (c != '\0') {
        LOG_WRN((
            "Data after key starting with 0x%2x. Ignoring remainder.\n",
            c));
    }

    return 0;
}

