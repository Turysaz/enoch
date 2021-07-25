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

#include "./common.h"
#include "./logging.h"
#include "./pontifex.h"

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
void px_kparse(char *keystr, char *keynum) {
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
            exit(EXIT_BADARGS);
        }

        k = atoi(numbuf);

        /* Validation */
        if (k < 1 || k > 54) {
            LOG_ERR (("Invalid card number: %i\n", k));
            exit(EXIT_BADARGS);
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

    return;
}

/*
 * Parses a key written as decimal numbers from a file
 * and saves it in the program args.
 */
void px_kread(struct px_args *args, char *filename) {
    FILE *kfile;
    char *buffer;
    int failure = 0,
        nread = 0;

    kfile = fopen(filename, "r");
    if (!kfile) {
        LOG_ERR(("Could not open '%s'!\n", filename));
        exit(EXIT_BADARGS);
    }

    nread = px_rall(kfile, &buffer);
    if (!nread) {
        LOG_ERR(("Empty key file!\n"));
        failure = EXIT_BADARGS;
        goto clean;
    }

    px_kparse(buffer, args->key);

    if (fclose(kfile)) {
        LOG_ERR(("Could not close keyfile.\n"));
        failure = EXIT_INTERNALERR;
        goto clean;
    }

clean:
    free(buffer);
    if (failure) exit(failure);
}

/*
 * Move a card in the deck from position oldi to
 * position newi
 */
static void px_move(char *deck, int oldi, int newi) {
    char buffer;
    int i;

    if (oldi == newi) return;

    buffer = deck[oldi];

    if (oldi < newi) {
        for (i = oldi; i < newi; i++) deck[i] = deck[i+1];
    } else {
        for (i = oldi; i > newi; i--) deck[i] = deck[i-1];
    }

    deck[newi] = buffer;
}

/*
 * Performs the first solitaire round, which is moving the
 * joker cards.
 */
static void px_mjokers(char *deck) {
    int i, j = 0;

    LOG_DBG(("Move jokers.\n"));

    for (i = 0; i < 54; i++) {
        if (deck[i] == 53) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR(("Could not locate joker A!\n"));
        exit(EXIT_BADARGS);
    }

    i = (j % 53) + 1;
    LOG_DBG(("Joker A from %i to %i.\n", j, i));
    px_move(deck, j, i);

    for (i = 0; i < 54; i++) {
        if (deck[i] == 54) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR(("Could not locate joker B!\n"));
        exit(EXIT_BADARGS);
    }

    i = (j % 53) + 1;
    i = (i % 53) + 1;
    LOG_DBG(("Joker B from %i to %i.\n", j, i));
    px_move(deck, j, i);
}

/*
 * Performs the second pontifex round, which is the
 * triple cut.
 */
static void px_tcut(char *deck) {
    int i,
        ja = -1,
        jb = -1,
        j1 = -1,
        j2 = -1;
    char buffer[54];
    int lp1, lp2, lp3; /* lengths of parts 1-3 */

    memset(buffer, 0, sizeof(buffer));

    for (i = 0; i < sizeof(buffer); i++) {
        if (deck[i] == 53) ja = i;
        if (deck[i] == 54) jb = i;
        if (ja >= 0 && jb >= 0) break;
    }

    if (ja < 0 || jb < 0) {
        LOG_ERR(("Could not locate jokers!\n"));
        exit(EXIT_BADARGS);
    }

    j1 = ja < jb ? ja : jb;
    j2 = ja > jb ? ja : jb;

    lp1 = j1;
    lp2 = j2-j1+1;
    lp3 = 53-j2;

    LOG_DBG((
        "Triple cut:\nj1: %i, j2: %i\nlengths: %i, %i, %i\n",
        j1, j2, lp1, lp2, lp3));

    memcpy(buffer, deck+j2+1, lp3);
    memcpy(buffer+lp3, deck+j1, lp2);
    memcpy(buffer+lp2+lp3, deck, lp1);

    memcpy(deck, &buffer, sizeof(buffer));

    /* Cleanup */
    memset(&buffer, 0, sizeof(buffer));
}

/*
 * Count-cut operation.
 * pwdkey:
 *   For the encryption and encryption, set the pwdkey to 0.
 *   When generating a key from a password, this needs to be
 *   set to the current password character.
 */
static void px_ccut(char *deck, char pwdkey) {
    char buffer[54];
    char count;

    memset(buffer, 0, sizeof(buffer));
    buffer[53] = deck[53];

    count = pwdkey == 0 ? deck[53] : pwdkey;

    /* Both jokers count as 53 */
    count = count == 54 ? 53 : count;

    LOG_DBG((
        "Count cut:\n"
        "Inserting %i cards to position %i,"
        " moving %i cards from position %i to front.\n",
        count, 53-count, 53-count, count));

    /*
     * Remember that the array indices start from zero,
     * but the lowest card value is 1.
     * Therefore, no additional +/-1 calc is necessary
     * for the "bottom card stays in place" thing.
     */

    memcpy(buffer + 53 - count, deck, count);
    memcpy(buffer, deck + count, 53 - count);

    memcpy(deck, &buffer, sizeof(buffer));

    /* Cleanup */
    memset(&buffer, 0, sizeof(buffer));
}

/*
 * Returns the next key stream letter, while modifying the deck.
 */
static char px_next(char *deck) {
    int offset;
    char next;

    do {
        px_mjokers(deck);
        px_tcut(deck);
        px_ccut(deck, 0);
        /* both jokers have the count val of 53. */
        offset = deck[0] <= 53 ? deck[0] : 53;

        next = deck[offset];
        if (next > 52) LOG_DBG(("Skipping output: %i\n", next));
    } while (next > 52);

    LOG_DBG((
        "Output: Top card: %i, taking %i from index %i.\n",
        deck[0], next, offset));

    return next;
}

/*
 * Generates the key based on a password.
 */
void px_genkey(char *password, char *key) {
    int i, n = 0;
    char c;

    /* initialize key */
    for (i = 0; i < 54; i++) key[i] = i+1;

    i = 0;
    while ((c = password[i++])) {
        if (!isalpha(c)) continue;
        n++;
        c = toupper(c);

        px_mjokers(key);
        px_tcut(key);
        px_ccut(key, 0);
        px_ccut(key, c - 0x40);
    }

    if (n < 64) {
        LOG_WRN((
            "Potentially weak password!"
            " At least 64 characters are recommended.\n"));
    }
}

/*
 * Returns the substitute for a single character m with the
 * key stream letter k with respect to the current mode
 * (encryption or decryption).
 */
char px_subst(char m, char k, enum px_mode mode) {
    char s; /* result */

    if (mode == PX_ENCR) {
        s = (m + k) % 26;
    } else if (mode == PX_DECR) {
        s = (52 + m - k) % 26;
    } else {
        LOG_ERR(("Invalid mode for operation. Abort!\n"));
        exit(EXIT_INTERNALERR);
    }

    s = s == 0 ? 26 : s;

    LOG_DBG(("SUBST: m: %i(%c), k:%i(%c), R: %i(%c)\n",
            m, m%26+0x40, k, k%26+0x40, s, s%26+0x40));
    return s;
}

/*
 * Reads a plain text or cipher text message from the input,
 * performs the encryption or decryption and prints the
 * result to the output.
 */
void px_cipher(struct px_args *args) {
    char deck[54];
    char *message = NULL, /* input buffer */
         *output = NULL; /* output buffer */
    char c, /* character read from buffer */
         k; /* key stream character */
    int i = 0, /* read index */
        o = 0, /* write index */
        nmessage; /* input buffer length */
    int failure = 0;

    memcpy(deck, args->key, 54);

    /* Read message */
    nmessage = px_rall(args->input, &message);
    if (!nmessage) {
        LOG_ERR(("Empty input, abort.\n"));
        goto clean;
    }

    /* Create output buffer, add 4 bytes for padding. */
    output = malloc((nmessage + 4) * sizeof(char));
    if (!output)
    {
        failure = EXIT_INTERNALERR;
        goto clean;
    }

    /* Cipher execution */
    while ((c = message[i++])) {
        if (!isalpha(c)) continue;
        c = toupper(c) - 0x40;
        k = px_next(deck);
        c = px_subst(c, k, args->mode);
        output[o++] = c + 0x40;
    }

    /* padding with X */
    while (o % 5) {
        c = 'X' - 0x40;
        k = px_next(deck);
        c = px_subst(c, k, args->mode);
        output[o++] = c + 0x40;
    }

    output[o] = '\0';

    /* Output */
    if (!args->raw && args->mode == PX_ENCR) {
        fprintf(args->output, "\n\n----- BEGIN PONTIFEX MESSAGE -----\n\n");
    }

    px_output(output, args->output);

    if (!args->raw && args->mode == PX_ENCR) {
        fprintf(args->output, "\n-----  END PONTIFEX MESSAGE  -----\n\n");
    }

    fputc('\n', args->output);

clean:
    memset(deck, 0, sizeof(deck));
    free(message);
    if (output) free(output);
    if (failure) exit(failure);
}

/*
 * Prints the key stream to the output.
 * The number of letters is defined within the args.
 */
void px_stream(struct px_args *args) {
    int i;
    char deck[54];
    char c;
    char *output;
    int failure = 0;

    memcpy(deck, args->key, sizeof(deck));

    output = malloc((args->length + 1) * sizeof(char));
    if (!output) {
        LOG_ERR(("Internal malloc error!\n"));
        failure = EXIT_INTERNALERR;
        goto clean;
    }

    for (i = 0; i < args->length; i++) {
        c = px_next(deck);
        c = c > 26 ? c - 26 : c;
        output[i] = c + 0x40;
    }
    output[args->length] = '\0';

    px_output(output, args->output);

clean:
    memset(deck, 0, sizeof(deck));
    if (failure) exit(failure);
}

/*
 * Print the current key to output.
 */
void px_pkey(struct px_args *args) {
    int i;
    for (i = 0; i < 54; i++) {
        fprintf(args->output, "%02i", args->key[i]);
    }
    fputc('\n', args->output);
}

