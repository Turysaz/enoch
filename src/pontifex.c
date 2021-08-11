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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "./common.h"
#include "./logging.h"
#include "./pontifex.h"

#include "./px_crypto.h"

/* ****************************************************************************
 * I/O helper functions
 */

/*
 * Returns the number of read chars, including the terminating NUL.
 */
static int px_rall(FILE *stream, char **content) {
    size_t bufsize = 1024,
           n = 0;
    char c;

    *content = malloc(bufsize * sizeof(char));
    if (!(*content)) goto err;

    while ((c = fgetc(stream)) != '\0' && !feof(stream)) {
        (*content)[n++] = c;
        if (n == bufsize) {
            *content = realloc(*content, (bufsize *=2) * sizeof(char));
            if (!*content) goto err;
        }
    }

    /* empty input */
    if (!n) return 0;

    *content = realloc(*content, n * sizeof(char));
    if (!*content) goto err;

    (*content)[n] = '\0';

    return n;

err:
    LOG_ERR(("Internal memory error!\n"));
    if (*content) free(*content);
    exit(EXIT_INTERNALERR);
}

/*
 * Prints the content of a zero-terminated buffer in groups of 5.
 */
static void px_output(const char *buffer, FILE *stream) {
    char c;
    int i = 0;
    while ((c = buffer[i++])) {
        fputc(c, stream);

        /* Grouping an linebreaks */
        if (i % 40 == 0 ) {
            fputc('\n', stream);
        } else if (i % 5 == 0) {
            fputc(' ', stream);
        }
    }

    fputc('\n', stream);
}

/*
 * Parses a key written as decimal numbers from the key string
 * to the byte array keynum.
 */
int px_kparse(char *keystr, char *keynum) {
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
        numbuf[1] = keystr[i*2+1];
        if (!isdigit(numbuf[0]) || !isdigit(numbuf[1])) {
            LOG_ERR((
                "Key not numeric or too short! "
                "Bad symbol at card #%i.\n",
                i + 1));
            return EINVAL;
        }

        k = atoi(numbuf);

        /* Validation */
        if (k < 1 || k > 54) {
            LOG_ERR (("Invalid card number: %i\n", k));
            return EINVAL;
        }

        if (used[k-1]++ != 0) {
            LOG_WRN(("The card %i occurs more than once!\n", k));
        }

        keynum[i] = k;
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

/*
 * Parses a key written as decimal numbers from a file
 * and saves it in the program args.
 */
int px_kread(struct px_oopts *args, char *filename) {
    FILE *kfile;
    char *buffer;
    int failure = 0,
        nread = 0;

    kfile = fopen(filename, "r");
    if (!kfile) {
        LOG_ERR(("Could not open '%s'!\n", filename));
        return EIO;
    }

    nread = px_rall(kfile, &buffer);
    if (!nread) {
        LOG_ERR(("Empty key file!\n"));
        failure = EINVAL;
        goto clean;
    }

    /* Note: the failure code may get overridden by the EIO
     * below. That's not nice, but accepted. */
    failure = px_kparse(buffer, args->key);

    if (fclose(kfile)) {
        LOG_ERR(("Could not close keyfile.\n"));
        failure = EIO;
        goto clean;
    }

clean:
    free(buffer);
    return failure;
}

/*
 * Generates the key based on a password.
 */
void px_genkey(char *password, char *key) {
    px_keygen(password, 0, key);
}

/*
 * Reads a plain text or cipher text message from the input,
 * performs the encryption or decryption and prints the
 * result to the output.
 */
void px_ocipher(struct px_oopts *args) {
    char *message = NULL, /* input buffer */
         *output = NULL; /* output buffer */
    struct px_opts opts = { 1 };
    int cryptexit = 0;
    int nmessage = 0;

    /* Read message */
    nmessage = px_rall(args->input, &message);
    if (!nmessage) {
        LOG_ERR(("Empty input, abort.\n"));
        goto clean;
    }

    if (args->mode == PX_ENCR) {
        cryptexit = px_encrypt(args->key, message, nmessage, &output, &opts);
    } else {
        cryptexit = px_decrypt(args->key, message, nmessage, &output, &opts);
    }

    if (cryptexit < 0 ) {
        LOG_ERR(("Error in crypto algorithm.\n"));
        goto clean;
    }

    /* Output */
    if (!args->raw && args->mode == PX_ENCR) {
        fprintf(args->output, "\n\n-----BEGIN PONTIFEX MESSAGE-----\n\n");
    }

    px_output(output, args->output);

    if (!args->raw && args->mode == PX_ENCR) {
        fprintf(args->output, "\n-----END PONTIFEX MESSAGE-----\n\n");
    }

    fputc('\n', args->output);

clean:
    free(message);
    if (output) free(output);
}

/*
 * Prints the key stream to the output.
 * The number of letters is defined within the args.
 */
void px_ostream(struct px_oopts *args) {
    char *output = NULL;
    struct px_opts opts = { 1 };

    if (px_stream(args->key, args->length, &output, &opts) != 0) {
        LOG_ERR(("Key stream generation failed.\n"))
        return;
    }

    px_output(output, args->output);
}

/*
 * Print the current key to output.
 */
void px_pkey(struct px_oopts *args) {
    int i;
    for (i = 0; i < 54; i++) {
        fprintf(args->output, "%02i", args->key[i]);
    }
    fputc('\n', args->output);
}

struct px_oopts px_defaultopts(void) {
    struct px_oopts options;
    int i;

    options.mode = PX_ENCR;
    options.input = stdin;
    options.output = stdout;
    options.raw = 0;
    options.movjok = 0;
    options.length = 5;

    for (i = 0; i < sizeof(options.key); i++) {
        options.key[i] = (char)i;
    }

    return options;
}

