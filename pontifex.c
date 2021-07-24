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
#include <argp.h>
#include <string.h>

static int loglevel = 0;
#define LOGLEVEL_ERR 0
#define LOGLEVEL_WRN 1
#define LOGLEVEL_INF 2
#define LOGLEVEL_DBG 3

#define LOGFILE stdout;

/* For variadic macros, especially for the '##' symbol, see:
 * https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html
 * TODO: Variadic macros are a C99 feature and should be
 *       replaced by some ANSI-C mechanism.
 */
#define LOG(level, format, ...) if (level <= loglevel) printf(format, ##__VA_ARGS__ );
#define LOG_ERR(format, ...) LOG(LOGLEVEL_ERR, "ERROR: " format, ##__VA_ARGS__ );
#define LOG_WRN(format, ...) LOG(LOGLEVEL_WRN, "WARNING: " format, ##__VA_ARGS__ );
#define LOG_INF(format, ...) LOG(LOGLEVEL_INF, format, ##__VA_ARGS__ );
#define LOG_DBG(format, ...) LOG(LOGLEVEL_DBG, format, ##__VA_ARGS__ );

#define EXIT_OKAY       0
#define EXIT_BADARGS   -1
#define EXIT_INTERNALERR -10

/* ****************************************************************************
 * I/O helper functions
 */

/*
 * Opens a file and exits on failure.
 */
static FILE *px_fopen(char *path, char *mode) {
    FILE *f = fopen(path, mode);
    if (!f) {
        LOG_ERR("Could not open '%s'!\n", path);
        exit(EXIT_BADARGS);
    }
    return f;
}

/*
 * Returns the number of read chars, including the terminating NUL.
 */
static int px_rall(FILE *stream, char **content) {
    size_t bufsize = 1024,
           n = 0;
    char c;

    *content = malloc(bufsize * sizeof(char));
    if (!(*content)) goto clean;

    while ((c = fgetc(stream)) != '\0' && !feof(stream)) {
        (*content)[n++] = c;
        if (n == bufsize) {
            *content = realloc(*content, (bufsize *=2) * sizeof(char));
            if (!*content) goto clean;
        }
    }

    *content = realloc(*content, n * sizeof(char));
    if (!*content) goto clean;

    (*content)[n] = '\0';

    return n;

clean: /* on error */
    LOG_ERR("Internal memory error!\n");
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

/* ****************************************************************************
 * Pontifex declarations and definitions
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
struct px_args {
    enum px_mode mode;
    char key[54];
    FILE *input;
    FILE *output;
    char raw;
    int length;
};

/*
 * Parses a key written as decimal numbers from the key string
 * to the byte array keynum.
 */
void px_kparse(char *keystr, char *keynum) {
    int i = 0;
    char numbuf[3] = { 0, 0, 0 };
    char c;

    while ((c = keystr[0]) == ' ' || c == 0x0a || c == 0x0d) {
        keystr += sizeof(char); /* move start of string to right */
        LOG_DBG("Ignoring whitespace before key...\n");
    }

    for (i = 0; i < 54; i++) {
        numbuf[0] = keystr[i*2];
        numbuf[1] = keystr[i*2+1];
        if (!isdigit(numbuf[0]) || !isdigit(numbuf[1])) {
            LOG_ERR(
                "Key not numeric or too short! "
                "Bad symbol at card #%i.\n",
                i + 1);
            exit(EXIT_BADARGS);
        }
        keynum[i] = atoi(numbuf);
    }

    i = 54 * 2; /* Set one byte past expected key. */
    while ((c = keystr[i++]) == ' ' || c == 0x0a || c == 0x0d) {
        LOG_DBG("Ignoring whitespace after key...\n");
    }

    if (c != '\0') {
        LOG_WRN(
            "Data after key starting with 0x%2x. Ignoring remainder.\n",
            c);
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
    int failure = 0;

    kfile = px_fopen(filename, "r");

    px_rall(kfile, &buffer);
    px_kparse(buffer, args->key);

    if (fclose(kfile)) {
        LOG_ERR("Could not close keyfile.\n");
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
void px_move(char *deck, int oldi, int newi) {
    char buffer;
    int i;

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
void px_mjokers(char *deck) {
    int i, j = 0;

    LOG_DBG("Move jokers.\n");

    for (i = 0; i < 54; i++) {
        if (deck[i] == 53) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR("Could not locate joker A!\n");
        exit(EXIT_BADARGS);
    }

    i = (j % 53) + 1;
    LOG_DBG("Joker A from %i to %i.\n", j, i);
    px_move(deck, j, i);

    for (i = 0; i < 54; i++) {
        if (deck[i] == 54) { j = i; break; }
    }

    if (j < 0) {
        LOG_ERR("Could not locate joker B!\n");
        exit(EXIT_BADARGS);
    }

    i = (j % 53) + 1;
    i = (i % 53) + 1;
    LOG_DBG("Joker B from %i to %i.\n", j, i);
    px_move(deck, j, i);
}

/*
 * Performs the second pontifex round, which is the
 * triple cut.
 */
void px_tcut(char *deck) {
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
        LOG_ERR("Could not locate jokers!\n");
        exit(EXIT_BADARGS);
    }

    j1 = ja < jb ? ja : jb;
    j2 = ja > jb ? ja : jb;

    lp1 = j1;
    lp2 = j2-j1+1;
    lp3 = 53-j2;

    LOG_DBG(
        "Triple cut:\nj1: %i, j2: %i\nlengths: %i, %i, %i\n",
        j1, j2, lp1, lp2, lp3);

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
void px_ccut(char *deck, char pwdkey) {
    char buffer[54];
    char count;

    memset(buffer, 0, sizeof(buffer));
    buffer[53] = deck[53];

    count = pwdkey == 0 ? deck[53] : pwdkey;

    LOG_DBG(
        "Count cut:\n"
        "Inserting %i cards to position %i,"
        " moving %i cards from position %i to front.\n",
        count, 53-count, 53-count, count);

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
char px_next(char *deck) {
    int offset;
    char next;

    do {
        px_mjokers(deck);
        px_tcut(deck);
        px_ccut(deck, 0);
        /* both jokers have the count val of 53. */
        offset = deck[0] <= 53 ? deck[0] : 53;

        next = deck[offset];
        if (next > 52) LOG_DBG("Skipping output: %i\n", next);
    } while (next > 52);

    LOG_DBG(
        "Output: Top card: %i, taking %i from index %i.\n",
        deck[0], next, offset);

    return next;
}

/*
 * Generates the key based on a password.
 */
void px_genkey(char *password, char *key) {
    int i;
    char c;

    /* initialize key */
    for (i = 0; i < 54; i++) key[i] = i+1;

    i = 0;
    while ((c = password[i++])) {
        if (!isalpha(c)) continue;
        c = toupper(c);

        px_mjokers(key);
        px_tcut(key);
        px_ccut(key, 0);
        px_ccut(key, c - 0x40);
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
        LOG_ERR("Invalid mode for operation. Abort!\n");
        exit(EXIT_INTERNALERR);
    }

    s = s == 0 ? 26 : s;

    LOG_DBG("SUBST: m: %i(%c), k:%i(%c), R: %i(%c)\n",
            m, m%26+0x40, k, k%26+0x40, s, s%26+0x40);
    return s;
}

/*
 * Reads a plain text or cipher text message from the input,
 * performs the encryption or decryption and prints the
 * result to the output.
 */
void px_cipher(struct px_args *args) {
    char deck[54];
    char *message, /* input buffer */
         *output; /* output buffer */
    char c, /* character read from buffer */
         k; /* key stream character */
    int i = 0, /* read index */
        o = 0, /* write index */
        nmessage; /* input buffer length */
    int failure = 0;

    memcpy(deck, args->key, 54);

    /* Read message */
    nmessage = px_rall(args->input, &message);

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
        LOG_ERR("Internal malloc error!\n");
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

/* ****************************************************************************
 * ARGP declarations and configuration
 */
const char *argp_program_version = "Pontifex 1.0";
const char *argp_program_bug_adrress = "<turysaz@posteo.org>";
static char px_doc[] =
    "For encrypting and decrypting using"
    " Bruce Schneier's pontifex algorithm.";
static char px_adoc[] = "";

static struct argp_option px_opts[] = {
    /* name      key      arg flags    doc                              group */
    { "encrypt", 'e',       0, 0, "Encrypt input. This is the default.",    0 },
    { "decrypt", 'd',       0, 0, "Decrypt input."                            },
    { "stream",  's',     "N", 0, "Just print N keystream symbols."           },
    { "input",   'i',  "FILE", 0, "Read input from FILE instead of stdin.", 1 },
    { "output",  'o',  "FILE", 0, "Write output to FILE instead of stdout."   },
    { "key",     'k',   "KEY", 0, "Define symmetric key.",                  2 },
    { "password",'p',"PASSWD", 0, "Use an alphabetic  passphrase"             },
    { "gen-key",   1,"PASSWD", 0, "Generate and print a passwd-based key."    },
    { "key-file",'f',  "FILE", 0, "Read key from FILE."                       },
    { "raw",     'r',       0, 0, "Skip PONTIFEX MESSAGE frame. (-e only)", 3 },
    { "verbose", 'v',       0, 0, "Increases verbosity (up to '-vvv')",       },
    { 0 }
};

/*
 * Parses an (unsigned) integer.
 */
static int px_pint(char *number) {
    char c;
    int i = 0;

    while ((c = number[i++])) {
        if (!isdigit(c)) {
            LOG_ERR("%s is not a integer!\n", number)
        }
    }

    return atoi(number);
}

/*
 * Parse options.
 */
static error_t px_popts(
        int key,
        char *arg,
        struct argp_state *state) {
    struct px_args *args = state->input;

    switch (key) {
        case 'e': /* --encrypt */
            LOG_INF("Encrypt mode.\n");
            args->mode = PX_ENCR;
            break;
        case 'd': /* --decrypt */
            LOG_INF("Decrypt mode.\n");
            args->mode = PX_DECR;
            break;
        case 's': /* --stream=N */
            LOG_INF("Stream mode.\n");
            args->mode = PX_STRM;
            args->length = px_pint(arg);
            break;
        case 'i': /* --input=FILE */
            LOG_INF("Reading input from '%s'\n", arg);
            args->input = px_fopen(arg, "r");
            break;
        case 'o': /* --output=FILE */
            LOG_INF("Writing output to '%s'\n", arg);
            args->output = px_fopen(arg, "w");
            break;
        case 'k': /* --key=KEY*/
            LOG_INF("Using key '%s'\n", arg);
            px_kparse(arg, args->key);
            break;
        case 'f': /* --key-file=FILE */
            LOG_INF("Using key from '%s'\n", arg);
            px_kread(args, arg);
            break;
        case   1: /* --gen-key=PASSWD */
            LOG_INF("Generating key from password");
            px_genkey(arg, args->key);
            args->mode = PX_PKEY;
            break;
        case 'p': /* --password=PASSWD */
            px_genkey(arg, args->key);
            break;
        case 'r': /* --raw */
            args->raw = 1;
            break;
        case 'v': /* --verbose */
            loglevel++;
            break;
        case ARGP_KEY_END:
            if (args->key[0] == -1) {
                argp_error(state, "No key was specified!\n");
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp px_parser = { px_opts, px_popts, px_adoc, px_doc };

int main(int argc, char **argv) {
    struct px_args args;

    /* set default values */
    args.mode = PX_ENCR;
    args.input = stdin;
    args.output = stdout;
    args.raw = 0;
    args.key[0] = -1;

    argp_parse(&px_parser, argc, argv, 0, 0, &args);

    switch (args.mode) {
        case PX_ENCR:
        case PX_DECR:
            px_cipher(&args);
            break;
        case PX_STRM:
            px_stream(&args);
            break;
        case PX_PKEY:
            px_pkey(&args);
            break;
    }

    return 0;
}

