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
#include <ctype.h>
#include <string.h>

#include "./px_crypto.h"
#include "./logging.h"

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
 * Returns 0 on failure, 1 on success.
 */
static int px_mjokers(char *deck) {
    int i, j = 0;

    LOG_DBG(("Move jokers.\n"));

    for (i = 0; i < 54; i++) {
        if (deck[i] == 53) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR(("Could not locate joker A!\n"));
        return 0;
    }

    i = (j % 53) + 1;
    LOG_DBG(("Joker A from %i to %i.\n", j, i));
    px_move(deck, j, i);

    for (i = 0; i < 54; i++) {
        if (deck[i] == 54) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR(("Could not locate joker B!\n"));
        return 0;
    }

    i = (j % 53) + 1;
    i = (i % 53) + 1;
    LOG_DBG(("Joker B from %i to %i.\n", j, i));
    px_move(deck, j, i);

    return 1;
}

/*
 * Performs the second pontifex round, which is the
 * triple cut.
 */
static int px_tcut(char *deck) {
    int i,
        ja = -1,
        jb = -1,
        j1 = -1,
        j2 = -1;
    char buffer[54];
    int lp1, lp2, lp3; /* lengths of parts 1-3 */
    int ret = 0;

    memset(buffer, 0, sizeof(buffer));

    for (i = 0; i < sizeof(buffer); i++) {
        if (deck[i] == 53) ja = i;
        if (deck[i] == 54) jb = i;
        if (ja >= 0 && jb >= 0) break;
    }

    if (ja < 0 || jb < 0) {
        LOG_ERR(("Could not locate jokers!\n"));
        goto clean;
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

    ret = 1;

clean:
    memset(&buffer, 0, sizeof(buffer));
    return ret;
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

    /*TODO adjust return value on error */
    do {
        if (!px_mjokers(deck)) return 100;
        if (!px_tcut(deck)) return 100;
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

#define PX_ENCR 0
#define PX_DECR 1

/*
 * Returns the substitute for a single character m with the
 * key stream letter k with respect to the current mode
 * (encryption = 0 or decryption = 1).
 */
static char px_subst(char m, char k, const int decrypt) {
    char s; /* result */

    if (decrypt) {
        s = (52 + m - k) % 26;
    } else {
        s = (m + k) % 26;
    }

    s = s == 0 ? 26 : s; /* Fake modulo... */

    LOG_DBG(("SUBST: m: %i(%c), k:%i(%c), R: %i(%c)\n",
            m, m%26+0x40, k, k%26+0x40, s, s%26+0x40));
    return s;
}

/*
 * TODO
 */
static int px_cipher(
    const char *key,
    const char *msg,
    const int nmsg,
    char **buf,
    const struct px_opts *opts,
    const int decrypt) {

    char deck[54]; /* copy of the key */
    char c, /* character read from buffer */
         k; /* key stream character */
    int i = 0, /* read index */
        o = 0; /* write index */
    int ret = -1;

    /* Input validation */
    if (key == NULL || msg == NULL || buf == NULL || opts == NULL) {
        ret = -1;
        LOG_ERR(("Null pointer found. Whoops. [473c]\n"));
        goto clean;
    }

    if (nmsg <= 0) {
        ret = 0;
        LOG_WRN(("Empty input, abort.\n"));
        goto clean;
    }

    memcpy(deck, key, 54);

    /* 
     * Create output buffer, add 4 bytes for 'X' padding and
     * one for a 0-terminator.
     */
    *buf = malloc((nmsg + 5) * sizeof(char));
    if (!*buf)
    {
        ret = -2;
        LOG_ERR(("No memory. [64a6]"));
        goto clean;
    }

    /* Cipher execution */
    while ((c = msg[i++]) && i <= nmsg) {
        if (!isalpha(c)) continue;
        c = toupper(c) - 0x40;
        k = px_next(deck);
        c = px_subst(c, k, decrypt);
        (*buf)[o++] = c + 0x40;
    }

    /* padding with X */
    while (o % 5) {
        c = 'X' - 0x40;
        k = px_next(deck);
        c = px_subst(c, k, decrypt);
        (*buf)[o++] = c + 0x40;
    }

    (*buf)[o++] = '\0';
    ret = o;

clean:
    memset(deck, 0, sizeof(deck));
    return ret;
}



/* Public header implementation */

/*
 * Encrypts a message using the pontifex algorithm.
 * See header.
 */
int px_encrypt(
    const char *key,
    const char *msg,
    const int nmsg,
    char **buf,
    const struct px_opts *opts) {

    return px_cipher(key, msg, nmsg, buf, opts, 0);
}

/**
 * Decrypts a message using the pontifex algorithm.
 * See header.
 */
int px_decrypt(
    const char *key,
    const char *msg,
    const int nmsg,
    char **buf,
    const struct px_opts *opts) {

    return px_cipher(key, msg, nmsg, buf, opts, 1);
}

/**
 * Generates letters of the key stream for the pontifex algorithm.
 * See header.
 */
int px_stream(
    const char *key,
    const int count,
    char **buf,
    const struct px_opts *opts) {

    int i;
    int ret = 0;
    char deck[54];
    char c;

    /* Input validation */
    if (key == NULL || buf == NULL || opts == NULL) {
        LOG_ERR(("Null pointer found. Whoops. [18b4]\n"));
        ret = -1;
        goto clean;
    }

    memcpy(deck, key, sizeof(deck));

    *buf = malloc((count + 1) * sizeof(char));
    if (!*buf) {
        LOG_ERR(("Internal malloc error! [6e79]\n"));
        ret = -1;
        goto clean;
    }

    for (i = 0; i < count; i++) {
        c = px_next(deck);
        c = c > 26 ? c - 26 : c;
        (*buf)[i] = c + 0x40;
    }

    (*buf)[count] = '\0';

clean:
    memset(deck, 0, sizeof(deck));
    return ret;
}


/**
 * Generates a key for the pontifex key stream algorithm based on a
 * password.
 * See header.
 */
int px_keygen(
    const char *password,
    const int mvjokers,
    char * const key) {

    int i, n = 0;
    char c;

    /* initialize key */
    for (i = 0; i < 54; i++) key[i] = i+1;

    i = 0;
    while ((c = password[i++])) {
        if (!isalpha(c)) continue;
        n++;
        c = toupper(c);

        if (!px_mjokers(key)) return -1;
        if (!px_tcut(key)) return -1;
        px_ccut(key, 0);
        px_ccut(key, c - 0x40);
    }

    if (n < 64) {
        LOG_WRN((
            "Potentially weak password!"
            " At least 64 characters are recommended.\n"));
    }
    
    return 0;
}

