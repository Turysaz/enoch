/*
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
    { "gen-key",  1 ,       0, 0, "Generate and print a passwd-based key."    },

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
 * Return:
 *      1 on success, 0 on failure
 */
static int trypint(char *number, int *result) {
    char c;
    int i = 0;

    while ((c = number[i++])) {
        if (!isdigit(c)) {
            LOG_ERR(("%s is not a integer!\n", number));
            return 0;
        }
    }

    *result = atoi(number);
    return 1;
}

struct pargs {
    char *inputf;
    char *outputf;
    char *keyf;
    char *keystr;
    char *pw;
    struct px_opts *options;
};

static void cleanpargs (struct pargs *arg) {
    char *c;

    if(!arg) {
        LOG_ERR(("Internal software error [134b]\n"));
        exit(EXIT_INTERNALERR);
    }

    arg->options = NULL;
    if (arg->pw) {
        c = arg->pw;
        while (*c != '\0') *(c++) = '\0';
        free(arg->pw);
        arg->pw = NULL;
    }
    if (arg->keyf) {
        c = arg->keyf;
        while (*c != '\0') *(c++) = '\0';
        free(arg->keyf);
        arg->keyf = NULL;
    }
    if (arg->keystr) {
        c = arg->keystr;
        while (*c != '\0') *(c++) = '\0';
        free(arg->keystr);
        arg->keystr = NULL;
    }
    if (arg->inputf) {
        free(arg->inputf);
        arg->inputf = NULL;
    }
    if (arg->outputf) {
        free(arg->outputf);
        arg->outputf = NULL;
    }
}

static struct pargs initpargs(struct px_opts *options) {
    struct pargs arguments;

    if(!options) {
        LOG_ERR(("Internal software error [2eb0]\n"));
        exit(EXIT_INTERNALERR);
    }

    /* set default values */
    arguments.inputf = NULL;
    arguments.outputf = NULL;
    arguments.keyf = NULL;
    arguments.keystr = NULL;
    arguments.pw = NULL;
    arguments.options = options;

    return arguments;
}

static error_t evalpargs(struct pargs *args) {
    int keydef = 0; /* Track how many options define the key.
                     * Should be 1. */
    error_t failure = 0;

    switch (args->options->mode) {
        case PX_ENCR: LOG_INF(("Encryption mode\n")); break;
        case PX_DECR: LOG_INF(("Decrytion mode\n")); break;
        case PX_STRM:
            LOG_INF((
                "Stream mode with %i symbols\n",
                args->options->length));
            break;
        case PX_PKEY:
            LOG_INF(("Print-key mode\n"));
            break;
    }

    if (args->options->raw) LOG_INF(("Output in raw mode\n"));

    if (args->pw) {
        LOG_INF(("Generating key from password.\n"));
        px_genkey(args->pw, args->options->key);
        keydef++;
    }
    if (args->keystr) {
        LOG_INF(("Using key '%s'\n", args->keystr));
        failure = px_kparse(args->keystr, args->options->key);
        keydef++;
    }
    if (args->keyf) {
        LOG_INF(("Using key file '%s'\n", args->keyf));
        failure = px_kread(args->options, args->keyf);
        keydef++;
    }

    if (failure) return failure; /* assuming the px_ funcs do the logging. */

    if (keydef != 1) {
        LOG_ERR(("Invalid key definition. Abort.\n"));
        return ENOTSUP;
    }

    if(args->inputf) {
        LOG_INF(("Reading input from '%s'\n", args->inputf));
        args->options->input = fopen(args->inputf, "r");
        if (!args->options->input) {
            LOG_ERR(("Could not open '%s'!\n", args->inputf));
            return ENOENT;
        }
    }

    if(args->outputf) {
        LOG_INF(("Writing output to '%s'\n", args->outputf));
        args->options->output = fopen(args->outputf, "w");
        if (!args->options->output) {
            LOG_ERR(("Could not open '%s'!\n", args->outputf));
            return ENOENT;
        }
    }

    return 0;
}

/*
 * Parse arguments.
 */
static error_t parseargs(
        int key,
        char *arg,
        struct argp_state *state) {
    struct pargs *args = state->input;
    size_t length;

    switch (key) {
        case 'e': /* --encrypt */
            args->options->mode = PX_ENCR;
            break;
        case 'd': /* --decrypt */
            args->options->mode = PX_DECR;
            break;
        case 's': /* --stream=N */
            args->options->mode = PX_STRM;
            if (!trypint(arg, &(args->options->length))) return ENOTSUP;
            break;
        case   1: /* --gen-key */
            args->options->mode = PX_PKEY;
            break;

        case 'i': /* --input=FILE */
            length = strlen(arg) + 1; /* + '\0' */
            args->inputf = malloc(length);
            if (!args->inputf) return ENOMEM;
            strncpy(args->inputf, arg, length);
            break;
        case 'o': /* --output=FILE */
            length = strlen(arg) + 1; /* + '\0' */
            args->outputf = malloc(length);
            if (!args->outputf) return ENOMEM;
            strncpy(args->outputf, arg, length);
            break;
        case 'k': /* --key=KEY*/
            length = strlen(arg) + 1; /* + '\0' */
            args->keystr = malloc(length);
            if (!args->keystr) return ENOMEM;
            strncpy(args->keystr, arg, length);
            break;
        case 'f': /* --key-file=FILE */
            length = strlen(arg) + 1; /* + '\0' */
            args->keyf = malloc(length);
            if (!args->keyf) return ENOMEM;
            strncpy(args->keyf, arg, length);
            break;
        case 'p': /* --password=PASSWD */
            length = strlen(arg) + 1; /* + '\0' */
            args->pw = malloc(length);
            if (!args->pw) return ENOMEM;
            strncpy(args->pw, arg, length);
            break;

        case 'j': /* --move-jokers */
            LOG_ERR(("NOT IMPLEMENTED\n"));
            args->options->movjok = 1;
            return ENOSYS;
            break;
        case 'r': /* --raw */
            args->options->raw = 1;
            break;
        case 'v': /* --verbose */
            loglevel++;
            break;
        case 'q': /* --quiet */
            loglevel = LOGLEVEL_ERR;
            break;
        case ARGP_KEY_END:
            return evalpargs(args);
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp parser = { opts, parseargs, adoc, doc };

int main(int argc, char **argv) {
    struct px_opts options;
    struct pargs arguments;
    error_t failure;

    options = px_defaultopts();
    arguments = initpargs(&options);

    failure = argp_parse(&parser, argc, argv, 0, 0, &arguments);
    cleanpargs(&arguments);

    if (failure) {
        LOG_ERR(("%s\n", strerror(failure)));
        exit(failure);
    }

    switch (options.mode) {
        case PX_ENCR:
        case PX_DECR:
            px_cipher(&options);
            break;
        case PX_STRM:
            px_stream(&options);
            break;
        case PX_PKEY:
            px_pkey(&options);
            break;
    }

    return 0;
}

