/*
 *  px_crypto.c : Contains the implementation of the cryptography
 *                algorithms.
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

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

#include "./px_crypto.h"
#include "./logging.h"

#define INVALID_CARD (card)254

/*
 * Move a card in the deck to another position.
 * Indices are zero-based.
 *
 * \param deck  Pointer to the deck, containing numbers 1-54.
 * \param oldi  Old position index.
 * \param newi  New position index.
 */
static void px_move(card *deck, int oldi, int newi) {
    card buffer;
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
 * Performs the first solitaire round.
 * It moves the joker cards forward.
 *
 * \param deck  Pointer to the deck, containing numbers 1-54.
 *
 * \returns 0 on failure, 1 on success.
 */
static int px_mjokers(card *deck) {
    int i, j;

    LOG_DBG(("Move jokers.\n"));

    j = -1;
    for (i = 0; i < 54; i++) {
        if (deck[i] == 53) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR(("Could not locate joker A!\n"));
        return 0;
    }

    i = (j % 53) + 1; /* Move 1 and wrap around if necessary. */
    LOG_DBG(("Joker A from %i to %i.\n", j, i));
    px_move(deck, j, i);

    j = -1;
    for (i = 0; i < 54; i++) {
        if (deck[i] == 54) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR(("Could not locate joker B!\n"));
        return 0;
    }

    i = (j % 53) + 1;
    i = (i % 53) + 1; /*Joker B needs this twice. */
    LOG_DBG(("Joker B from %i to %i.\n", j, i));
    px_move(deck, j, i);

    return 1;
}

/*
 * Performs the second solitaire round, which is the triple cut.
 *
 * \param deck  Pointer to the deck, containing numbers 1-54.
 *
 * \returns 1 on success, 0 on failure.
 */
static int px_tcut(card *deck) {
    int i,
        ja = -1, /* joker indices */
        jb = -1,
        j1 = -1,
        j2 = -1;
    card buffer[54];
    int lp1, lp2, lp3; /* lengths of parts 1-3 */
    int ret = 0;

    memset(buffer, 0, sizeof(buffer));

    /* locate jokers */
    for (i = 0; i < sizeof(buffer); i++) {
        if (deck[i] == 53) ja = i;
        if (deck[i] == 54) jb = i;
        if (ja >= 0 && jb >= 0) break;
    }

    if (ja < 0 || jb < 0) {
        LOG_ERR(("Could not locate jokers!\n"));
        goto clean;
    }

    /* get joker order and sizes of the three parts */
    j1 = ja < jb ? ja : jb;
    j2 = ja > jb ? ja : jb;
    lp1 = j1;
    lp2 = j2-j1+1;
    lp3 = 53-j2;

    LOG_DBG((
        "Triple cut:\nj1: %i, j2: %i\nlengths: %i, %i, %i\n",
        j1, j2, lp1, lp2, lp3));

    /* rearrange parts */
    memcpy(buffer, deck+j2+1, lp3);
    memcpy(buffer+lp3, deck+j1, lp2);
    memcpy(buffer+lp2+lp3, deck, lp1);

    /* write back to original deck */
    memcpy(deck, &buffer, sizeof(buffer));

    ret = 1;

clean:
    memset(&buffer, 0, sizeof(buffer));
    return ret;
}

/*
 * Performs the third solitaire round, the count cut.
 *
 * \param deck  Pointer to the deck, containing numbers 1-54.
 *
 * \param pwdkey For the encryption and encryption, set the pwdkey to 0.
 *               When generating a key from a password, this needs to be
 *               set to the current password character.
 */
static void px_ccut(card *deck, char pwdkey) {
    card buffer[54];
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
 * Returns the next key stream card, while modifying the deck.
 * The returned letter is a number from 1 to 52, not an ASCII char!
 *
 * Note that this will never yield a joker card!
 *
 * \param deck  Pointer to the deck, containing numbers 1-54.
 *
 * \returns values 1-52 normally, INVALID_CARD on error.
 */
static card px_next(card *deck) {
    int offset;
    card next;

    do {
        if (!px_mjokers(deck)) return INVALID_CARD;
        if (!px_tcut(deck)) return INVALID_CARD;
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
 * Cipher character substitution.
 *
 * Returns the substitute for a single character m with the
 * key stream letter k with respect to the current mode.
 *
 * \param m       Message character (1-26).
 * \param k       Key character/card (1-52).
 * \param decrypt Mode: 1 = decrypt, 0 = encrypt
 * \returns Substituted character (1-26).
 */
static card px_subst(card m, card k, const int decrypt) {
    char s; /* result */

    if (decrypt) {
        s = (52 + m - k) % 26;
    } else {
        s = (m + k) % 26;
    }

    s = s == 0 ? 26 : s; /* Fake modulo... */

    LOG_DBG(("SUBST: m: %i(%c), k:%i(%c), R: %i(%c)\n",
            m, CARD2ASCII(m),
            k, CARD2ASCII(k),
            s, CARD2ASCII(s)));
    return s;
}

/*
 * Performs the pontifex cipher algorithm, both for
 * encrypting and decrypting.
 *
 * \param   key     Pointer to 54-byte card deck.
 * \param   msg     Pointer to message to work cipher on.
 * \param   nmsg    Length of message.
 * \param   buf     out: Pointer to the result.
 * \param   px_opts Pointer to the options struct.
 * \param   decrypt Encrypt if 1, decrypt if 0.
 *
 * \returns Length of result including 0-terminator.
 */
static int px_cipher(
    const card *key,
    const char *msg,
    const int nmsg,
    char **buf,
    const struct px_opts *opts,
    const int decrypt) {

    card deck[54]; /* copy of the key */
    card k; /* key stream character */
    char c; /* character read from buffer */
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
        ret = 0; /* Not an error! */
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
        LOG_ERR(("No memory. [64a6]\n"));
        goto clean;
    }

    /* Cipher execution */
    while ((c = msg[i++]) && i <= nmsg) {
        if (!isalpha(c)) continue;
        c = ASCII2CARD(c);
        if((k = px_next(deck)) == INVALID_CARD) {
            ret = -3;
            LOG_ERR(("Error on getting next key stream letter [20ba].\n"));
            goto clean;
        }
        c = px_subst(c, k, decrypt);
        (*buf)[o++] = CARD2ASCII(c);
    }

    if (i > nmsg + 1) {
        LOG_WRN(
            ("The message appears longer than specified."
            " Parts of the message may remain unencrypted!\n"));
    }

    /* padding with X */
    while (o % 5) {
        c = ASCII2CARD('X');
        if((k = px_next(deck)) == INVALID_CARD) {
            ret = -4;
            LOG_ERR(("Error on getting next key stream letter. [5138]\n"));
            goto clean;
        }

        c = px_subst(c, k, decrypt);
        (*buf)[o++] = CARD2ASCII(c);
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
    const card *key,
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
    const card *key,
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
    const card *key,
    const int count,
    char **buf,
    const struct px_opts *opts) {

    int i;
    int ret = 0;
    card deck[54];
    card c;

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
        if((c = px_next(deck)) == INVALID_CARD) {
            ret = -2;
            LOG_ERR(("Error on getting next key stream letter. [3de8]\n"));
            goto clean;
        }

        (*buf)[i] = CARD2ASCII(c);
    }

    (*buf)[count] = '\0';

clean:
    memset(deck, 0, sizeof(deck));
    return ret;
}

/**
 * ("Key-Move-Jokers")
 * Relocate the jokers to the positions given by the last two
 * cards in the deck.
 * This is an optional step for key generation.
 */
static int px_kmovj(card * const key) {
    int j;
    char ja_n, jb_n, ja = 0, jb = 0;

    /* Get the last two cards.
       The +1 offset of the non-zero-based card numbers is
       okay since the jokers shall go _behind_ the numbers. */
    ja_n = key[52];
    jb_n = key[53];
    if (ja_n > 53) ja_n = 53;
    if (jb_n > 53) jb_n = 53;

    /* Find the jokers */
    for (j = 0; j < 54; j++) {
        if (key[j] == 53) ja = j;
        if (key[j] == 54) jb = j;
    }

    assert(ja != 0 && jb != 0 && ja != jb);

    /* px_move() puts the card to a new position _after_ removing
       it. However, after removing it, the index may have changed.
       Therefore, the new index has to be adjusted in the cases below.
       This behavior is _not_ defined by B. Schneier. */
    if (ja < ja_n) { ja_n--; }
    if (jb < jb_n) { jb_n--; }

    /* Relocate joker A */
    px_move(key, ja, ja_n);

    /* Adjust JB's position after moving JA, if necessary */
    if (ja < jb && ja_n > jb) {
        /* JA's current position is before JB,
           its new position is behind it. */
        jb--;
    } else if (ja > jb && ja_n < jb) {
        jb++; /* JA moved before JB */
    }

    /* Relocate joker B */
    px_move(key, jb, jb_n);

    return 0;
}

/**
 * Generates a key for the pontifex key stream algorithm based on a
 * password.
 * See header.
 */
int px_keygen(
    const char *password,
    const int mvjokers,
    card * const key) {

    int i,
        n = 0; /* counter for characters in password */
    char c; /* current character */

    /* initialize key */
    for (i = 0; i < 54; i++) key[i] = i+1;

    i = 0;
    while ((c = password[i++])) {
        if (!isalpha(c)) continue;
        n++;

        if (!px_mjokers(key)) return -1;
        if (!px_tcut(key)) return -1;
        px_ccut(key, 0);
        px_ccut(key, ASCII2CARD(c));

        if (mvjokers) {
            px_kmovj(key);
        }
    }

    if (n < 64) {
        LOG_WRN((
            "Potentially weak password!"
            " At least 64 characters are recommended.\n"));
    }

    return 0;
}

#undef INVALID_CARD

