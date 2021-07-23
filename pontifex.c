/*
 *  Implementation of Bruce Schneier's Pontifex/Solitaire cryptosystem.
 *  Copyright (C) 2021 Turysaz
 *
 *  This is free software as defined by the Free Software Foundation
 *  and licensed to you under the terms of the General Public License v2
 *  (GPLv2).
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
 * */
#define LOG(level, format, ...) if (level <= loglevel) printf(format, ##__VA_ARGS__ );
#define LOG_ERR(format, ...) LOG(LOGLEVEL_ERR, "ERROR: " format, ##__VA_ARGS__ );
#define LOG_WRN(format, ...) LOG(LOGLEVEL_WRN, "WARNING: " format, ##__VA_ARGS__ );
#define LOG_INF(format, ...) LOG(LOGLEVEL_INF, format, ##__VA_ARGS__ );
#define LOG_DBG(format, ...) LOG(LOGLEVEL_DBG, format, ##__VA_ARGS__ );

#define EXIT_OKAY       0
#define EXIT_BADARGS   -1
#define EXIT_INTERNALERR -10

/* **************************************************************************** 
 * Pontifex declarations and definitions
 */

/*
 *  Defines the operation modes: encrypt or decrypt.
 */
enum px_mode { PX_ENCR, PX_DECR };

/*
 *  This structs contains the evaluated settings
 *  defined by the CLI options.
 */
struct px_args {
    enum px_mode mode;
    FILE *input;
    FILE *output;
    char key[54];
    char raw;
};

void px_kparse(char *keystr, char *keynum) {
    int i;
    char numbuf[3] = { 0, 0, 0 };

    for (i = 0; i < 54; i++){
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

    if (keystr[54*2] != '\0') {
        LOG_ERR("Key too long!\n");
        exit(EXIT_BADARGS);
    }

    return;
}

/*
 * Returns the number of read chars, including the terminating NUL.
 */
int px_rall(FILE *stream, char **content) {
    size_t bufsize = 1024,
           n = 0;
    char c;

    *content = malloc(bufsize * sizeof(char));
    if (!(*content)) goto clean;

    while((c = fgetc(stream)) != '\0' && !feof(stream)) {
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

clean:
    LOG_ERR("Internal realloc error!\n");
    if (*content) free(*content);
    exit(EXIT_INTERNALERR);
}

void move(char *deck, int oldi, int newi) {
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

void px_mjokers(char *deck) {
    int i, j;

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
    move(deck, j, i);

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
    move(deck, j, i);
}

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

    if(ja < 0 || jb < 0) {
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

void px_ccut(char *deck) {
    char buffer[54];
    char count;

    memset(buffer, 0, sizeof(buffer));
    count = deck[53];
    buffer[53] = count;

    LOG_DBG(
        "Count cut:\n"
        "Inserting %i cards to position %i,"
        " moving %i cards from position %i to front.\n",
        count, 53-count, 53-count, count);

    memcpy(buffer + 53 - count, deck, count);
    memcpy(buffer, deck + count, 53 - count);

    memcpy(deck, &buffer, sizeof(buffer));

    /* Cleanup */
    memset(&buffer, 0, sizeof(buffer));
}

char px_next(char *deck) {
    int offset;
    char next;

    do {
        px_mjokers(deck);
        px_tcut(deck);
        px_ccut(deck);
        /* both jokers have the count val of 53. */
        offset = deck[0] <= 53 ? deck[0] : 53;

        next = deck[offset];
        if(next > 52) LOG_DBG("Skipping output: %i\n", next);
    } while (next > 52);

    LOG_DBG(
        "Output: Top card: %i, taking %i from index %i.\n",
        deck[0], next, offset);

    return next;
}

char px_subst(char m, char k, enum px_mode mode) {
    char s; /* result */

    s = mode == PX_ENCR 
        ? (m + k) % 26 
        : (52 + m - k) % 26;

    s = s == 0 ? 26 : s;

    LOG_DBG("SUBST: m: %i(%c), k:%i(%c), R: %i(%c)\n",
            m, m%26+0x40, k, k%26+0x40, s, s%26+0x40);
    return s;
}

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

    /* Create output buffer */
    output = malloc(nmessage * sizeof(char));
    if (!output)
    {
        failure = EXIT_INTERNALERR;
        goto clean;
    }

    /* Cipher execution */
    while((c = message[i++])) {
        if (!isalpha(c)) continue;
        c = toupper(c) - 0x40;
        k = px_next(deck);
        c = px_subst(c, k, args->mode);
        output[o++] = c + 0x40;
    }
    output[o] = '\0';

    /* Output */
    if (!args->raw && args->mode == PX_ENCR) {
        fprintf(
            args->output,
            "\n\n=========== BEGIN PONTIFEX MESSAGE ============\n\n");
    }

    i = 0;
    while((c = output[i++])) {
        fputc(c, args->output);

        /* Grouping an linebreaks */
        if (i % 40 == 0 ) {
            fputc('\n', args->output);
        } else if (i % 5 == 0) {
            fputc(' ', args->output);
        }
    }

    if (!args->raw && args->mode == PX_ENCR) {
        fprintf(
            args->output,
            "\n\n===========  END PONTIFEX MESSAGE  ============\n");
    }

    fputc('\n', args->output);

clean:
    free(message);
    if (output) free(output);
    if (failure) exit(failure);
}

static FILE *px_fopen(char *path, char *mode) {
    FILE *f = fopen(path, mode);
    if (!f) {
        LOG_ERR("Could not open '%s'!\n", path);
        exit(EXIT_BADARGS);
    }
    return f;
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
    { "stream",  's',     "N", 0, "Just print N keystream numbers."           },
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
 * popts = parse opts
 */
static error_t px_popts(
        int key,
        char *arg,
        struct argp_state *state) {
    struct px_args *args = state->input;

    switch (key) {
        case 'e':
            LOG_INF("Encrypt mode.\n");
            args->mode = PX_ENCR;
            break;
        case 'd':
            LOG_INF("Decrypt mode.\n");
            args->mode = PX_DECR;
            break;
        case 'i':
            /* TODO malicious args possible?*/
            LOG_INF("Reading input from '%s'\n", arg);
            args->input = px_fopen(arg, "r");
            break;
        case 'o':
            LOG_INF("Writing output to '%s'\n", arg);
            args->output = px_fopen(arg, "w");
            break;
        case 'k':
            LOG_INF("Using key '%s'\n", arg);
            px_kparse(arg, args->key);
            break;
        case 'p':
        case   1:
        case 's':
        case 'f':
            LOG_ERR("Reading key file not implemented yet.\n");
            exit(-99);
            break;
        case 'r':
            args->raw = 1;
            break;
        case 'v':
            loglevel++;
            break;
/*
        case ARGP_KEY_ARG:
            break;
*/
        case ARGP_KEY_END:
            if (args->key[0] == -1){
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

    /* TODO the buffer thing is a temp hack */
    char msgbuf[1024];
    memset(msgbuf, 0, sizeof(msgbuf));

    /* set default values */
    args.mode = PX_ENCR;
    args.input = stdin;
    args.output = stdout;
    args.raw = 0;
    args.key[0] = -1;

    argp_parse(
            &px_parser,
            argc,
            argv,
            0,
            0,
            &args);

    px_cipher(&args);

    return 0;
}

