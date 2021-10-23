/*
 *  enoch.c : This is the main entry for the program, containing the
 *            main() function.
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

#include <argp.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./logging.h"
#include "./px_crypto.h"
#include "./px_io.h"

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
    { "raw",     'r',       0, 0, "Skip PONTIFEX MESSAGE frame. (-e / -d)", 3 },
    { "verbose", 'v',       0, 0, "Increases verbosity (up to '-vv')"         },
    { "quiet",   'q',       0, 0, "Reduces all log output except errors"      },
    { 0 }
};

/*
 *  Defines the operation modes.
 */
enum runmode {
    MD_ENCR, /* Encrypt message */
    MD_DECR, /* Decrypt message */
    MD_STRM, /* Print key stream */
    MD_PKEY  /* Generate and print key */
};

/*
 *  This structs contains the evaluated settings
 *  defined by the CLI options.
 */
struct runopts {
    enum runmode mode;
    char key[54];
    FILE *input;
    FILE *output;
    char raw; /* bool flag: raw output */
    char movjok; /* bool flag: move jokers on key generation */
    int length; /* output length */
};

/*
 * This struct collects the unevaluated CLI options, such
 * as file names.
 */
struct cliargs {
    char *inputf;
    char *outputf;
    char *keyf;
    char *keystr;
    char *pw;
    struct runopts *options;
};

/*
 * Initializes default options.
 */
struct runopts _defrunopts(void) {
    struct runopts options;
    int i;

    options.mode = MD_ENCR;
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

static void _clrrunopts (struct runopts *opts) {
    if(opts->input != stdin) fclose(opts->input);
    if(opts->output != stdout) fclose(opts->output);
}

/*
 *  Initializes a default CLI argument collector.
 */
static struct cliargs _defcliargs(struct runopts *options) {
    struct cliargs arguments;

    if(!options) {
        LOG_ERR(("Internal software error [2eb0]\n"));
        exit(ENOTSUP);
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

/*
 *  Cleans the content of the cliargs argument.
 */
static void _clrcliargs (struct cliargs *arg) {
    char *c;

    if(!arg) {
        LOG_ERR(("Internal software error [134b]\n"));
        exit(ENOTSUP);
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

/*
 * Returns the number of read chars, including the terminating NUL.
 */
static int _readall(FILE *stream, char **content) {
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

    (*content)[n-1] = '\0';

    return n;

err:
    LOG_ERR(("Internal memory error!\n"));
    if (*content) free(*content);
    exit(ENOMEM);
}

/*
 * Prints the content of a zero-terminated buffer in groups of 5.
 */
static void _outgrp(const char *buffer, FILE *stream) {
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
 * Parses a key written as decimal numbers from a file
 * and saves it in the program args.
 */
static int _readkey(char *key, char *filename) {
    FILE *kfile;
    char *buffer;
    int failure = 0,
        nread = 0;

    kfile = fopen(filename, "r");
    if (!kfile) {
        LOG_ERR(("Could not open '%s'!\n", filename));
        return EIO;
    }

    nread = _readall(kfile, &buffer);
    if (!nread) {
        LOG_ERR(("Empty key file!\n"));
        failure = EINVAL;
        goto clean;
    }

    /* Note: the failure code may get overridden by the EIO
     * below. That's not nice, but accepted. */
    failure = px_rdkey(buffer, key);

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
 * Reads a plain text or cipher text message from the input,
 * performs the encryption or decryption and prints the
 * result to the output.
 * TODO: Replace by lib functions!
 */
void _cipher(struct runopts *args) {
    char *filebuf = NULL, /* buffer for raw file content*/
         *message = NULL, /* input buffer */
         *output = NULL; /* output buffer */
    struct px_opts opts = { 1 };
    int cryptexit = 0;
    int nmessage = 0;
    unsigned int flags = 0;

    /* Read message */
    nmessage = _readall(args->input, &filebuf);

    /* Set the message to raw content by default. Important for freeing. */
    message = filebuf;

    if (!nmessage) {
        LOG_ERR(("Empty input, abort.\n"));
        goto clean;
    }

    if (args->mode == MD_ENCR) {
        cryptexit = px_encrypt(args->key, message, nmessage, &output, &opts);
        if (cryptexit < 0) {
            LOG_ERR(("Error in crypto algorithm.\n"));
            goto clean;
        }

        if(args->raw) flags |= PXO_RAW;
        px_prcipher(output, args->output, flags);
    } else {
        if (!args->raw) {
            nmessage = px_rdcipher(filebuf, &message);
            free(filebuf); /* The raw content is no longer needed. */
            if (nmessage == -1) {
                LOG_ERR(("The message was malformed.\n"))
                goto clean;
            }
        }

        cryptexit = px_decrypt(args->key, message, nmessage, &output, &opts);
        if (cryptexit < 0) {
            LOG_ERR(("Error in crypto algorithm.\n"));
            goto clean;
        }

        fprintf(args->output, "%s\n", output);
    }

clean:
    if (message) free(message);
    if (output) free(output);
}

/*
 * Prints the key stream to the output.
 * The number of letters is defined within the args.
 */
static void _stream(struct runopts *args) {
    char *output = NULL;
    struct px_opts opts = { 1 };

    if (px_stream(args->key, args->length, &output, &opts) != 0) {
        LOG_ERR(("Key stream generation failed.\n"))
        return;
    }

    _outgrp(output, args->output);

    if (output) free(output);
}

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

static error_t _evalpargs(struct cliargs *args) {
    int keydef = 0; /* Track how many options define the key.
                     * Should be 1. */
    error_t failure = 0;

    switch (args->options->mode) {
        case MD_ENCR: LOG_INF(("Encryption mode\n")); break;
        case MD_DECR: LOG_INF(("Decrytion mode\n")); break;
        case MD_STRM:
            LOG_INF((
                "Stream mode with %i symbols\n",
                args->options->length));
            break;
        case MD_PKEY:
            LOG_INF(("Print-key mode\n"));
            break;
    }

    if (args->options->raw) LOG_INF(("Output in raw mode\n"));

    if (args->pw) {
        LOG_INF(("Generating key from password.\n"));
        px_keygen(args->pw, args->options->movjok, args->options->key);
        keydef++;
    }
    if (args->keystr) {
        LOG_INF(("Using key '%s'\n", args->keystr));
        failure = px_rdkey(args->keystr, args->options->key);
        keydef++;
    }
    if (args->keyf) {
        LOG_INF(("Using key file '%s'\n", args->keyf));
        failure = _readkey(args->options->key, args->keyf);
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
    struct cliargs *args = state->input;
    size_t length;

    switch (key) {
        case 'e': /* --encrypt */
            args->options->mode = MD_ENCR;
            break;
        case 'd': /* --decrypt */
            args->options->mode = MD_DECR;
            break;
        case 's': /* --stream=N */
            args->options->mode = MD_STRM;
            if (!trypint(arg, &(args->options->length))) return ENOTSUP;
            break;
        case   1: /* --gen-key */
            args->options->mode = MD_PKEY;
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
            args->options->movjok = 1;
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
            return _evalpargs(args);
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp parser = { opts, parseargs, adoc, doc };

int main(int argc, char **argv) {
    struct runopts options;
    struct cliargs arguments;
    error_t failure;

    options = _defrunopts();
    arguments = _defcliargs(&options);

    failure = argp_parse(&parser, argc, argv, 0, 0, &arguments);
    _clrcliargs(&arguments);

    if (failure) {
        LOG_ERR(("%s\n", strerror(failure)));
        exit(failure);
    }

    switch (options.mode) {
        case MD_ENCR:
        case MD_DECR:
            _cipher(&options);
            break;
        case MD_STRM:
            _stream(&options);
            break;
        case MD_PKEY:
            px_prkey(options.key, options.output, PXO_RAW);
            break;
    }

    _clrrunopts(&options);

    return 0;
}

