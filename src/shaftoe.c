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
#include <string.h>
#include <argp.h>

#include "./common.h"
#include "./logging.h"
#include "./pontifex.h"

int loglevel = LOGLEVEL_WRN;

/* ****************************************************************************
 * ARGP declarations and configuration
 */
const char *argp_program_version = "0.1";
const char *argp_program_bug_adrress = "<turysaz@posteo.org>";
static char doc[] =
    "Implementation of Bruce Schneier's solitaire/pontifex cryptosystem.";
static char adoc[] = "";

static struct argp_option opts[] = {
    /* name      key      arg flags    doc                              group */
    /* Operation modes */
    { "encrypt", 'e',       0, 0, "Encrypt input. This is the default.",    0 },
    { "decrypt", 'd',       0, 0, "Decrypt input."                            },
    { "stream",  's',     "N", 0, "Just print N keystream symbols."           },
    { "gen-key",  1 ,"PASSWD", 0, "Generate and print a passwd-based key."    },

    /* I/O definition */
    { "input",   'i',  "FILE", 0, "Read input from FILE instead of stdin.", 1 },
    { "output",  'o',  "FILE", 0, "Write output to FILE instead of stdout."   },

    /* key definition */
    { "key",     'k',   "KEY", 0, "Define symmetric key.",                  2 },
    { "password",'p',"PASSWD", 0, "Use an alphabetic  passphrase"             },
    { "key-file",'f',  "FILE", 0, "Read key from FILE."                       },
    { 
        "move-jokers",
        'j',
        0,
        0,
        "Move jokers for key generation. (-p or --gen-key only)"
    },

    /* behavior */
    { "raw",     'r',       0, 0, "Skip PONTIFEX MESSAGE frame. (-e only)", 3 },
    { "verbose", 'v',       0, 0, "Increases verbosity (up to '-vv')"         },
    { "quiet",   'q',       0, 0, "Reduces all log output except errors"      },
    { 0 }
};

/*
 * Parses an (unsigned) integer.
 */
static int pint(char *number) {
    char c;
    int i = 0;

    while ((c = number[i++])) {
        if (!isdigit(c)) {
            LOG_ERR(("%s is not a integer!\n", number));
        }
    }

    return atoi(number);
}

/*
 * Parse options.
 */
static error_t popts(
        int key,
        char *arg,
        struct argp_state *state) {
    struct px_args *args = state->input;

    switch (key) {
        case 'e': /* --encrypt */
            LOG_INF(("Encrypt mode.\n"));
            args->mode = PX_ENCR;
            break;
        case 'd': /* --decrypt */
            LOG_INF(("Decrypt mode.\n"));
            args->mode = PX_DECR;
            break;
        case 's': /* --stream=N */
            LOG_INF(("Stream mode.\n"));
            args->mode = PX_STRM;
            args->length = pint(arg);
            break;
        case   1: /* --gen-key=PASSWD */
            LOG_INF(("Generating key from password"));
            px_genkey(arg, args->key);
            args->mode = PX_PKEY;
            break;
        case 'i': /* --input=FILE */
            LOG_INF(("Reading input from '%s'\n", arg));
            args->input = fopen(arg, "r");
            if (!args->input) {
                LOG_ERR(("Could not open '%s'!\n", arg));
                exit(EXIT_BADARGS);
            }
            break;
        case 'o': /* --output=FILE */
            LOG_INF(("Writing output to '%s'\n", arg));
            args->output = fopen(arg, "w");
            if (!args->output) {
                LOG_ERR(("Could not open '%s'!\n", arg));
                exit(EXIT_BADARGS);
            }
            break;
        case 'k': /* --key=KEY*/
            LOG_INF(("Using key '%s'\n", arg));
            px_kparse(arg, args->key);
            break;
        case 'f': /* --key-file=FILE */
            LOG_INF(("Using key from '%s'\n", arg));
            px_kread(args, arg);
            break;
        case 'p': /* --password=PASSWD */
            px_genkey(arg, args->key);
            break;
        case 'j': /* --move-jokers */
            /*TODO: handle argument-order problem first. */
            LOG_ERR(("NOT IMPLEMENTED"));
            break;
        case 'r': /* --raw */
            args->raw = 1;
            break;
        case 'v': /* --verbose */
            loglevel++;
            break;
        case 'q': /* --quiet */
            loglevel = LOGLEVEL_ERR;
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

static struct argp parser = { opts, popts, adoc, doc };

int main(int argc, char **argv) {
    struct px_args args;

    /* set default values */
    args.mode = PX_ENCR;
    args.input = stdin;
    args.output = stdout;
    args.raw = 0;
    memset(args.key, 0, sizeof(args.key));
    args.key[0] = -1;

    argp_parse(&parser, argc, argv, 0, 0, &args);

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

