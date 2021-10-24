# Enoch

ANSI C implementation of
[Bruce Schneier's](https://www.schneier.com/academic/solitaire/)
playing card based *Solitaire* symmetric crypto system, that's
being used by the characters in Neil Stephenson's novel
*Cryptonomicon*.

## Features

* encryption and decryption
* password-based key generation
* explicit key definition
* output of password-generated keys
* key stream output
* C89

*("Key" means the card deck order)*

## Example

```bash
$ # encrypt:
$ enoch -p cryptonomicon | tee out.txt
solitaire
^D
-----BEGIN PONTIFEX MESSAGE-----
KIRAK SFJAN 
-----END PONTIFEX MESSAGE-----

$ # decrypt:
$ enoch -d -p cryptonomicon -i out.txt
SOLITAIREX

$ # print 40 characters of key stream
$ enoch -p foobar -s 40
AHCIM TKLCX XZSFC KYAJD KTZWY CXJWI LYTUG ACQTM

```

## Usage

```bash
$ enoch --help
Usage: enoch [OPTION...] 
Implementation of Bruce Schneier's solitaire/pontifex cryptosystem.

  -d, --decrypt              Decrypt input.
  -e, --encrypt              Encrypt input. This is the default.
      --gen-key              Generate and print a passwd-based key.
  -s, --stream=N             Just print N keystream symbols.
  -i, --input=FILE           Read input from FILE instead of stdin.
  -o, --output=FILE          Write output to FILE instead of stdout.
  -f, --key-file=FILE        Read key from FILE.
  -j, --move-jokers          Move jokers for key generation. (-p or --gen-key
                             only)
  -k, --key=KEY              Define symmetric key.
  -p, --password=PASSWD      Use an alphabetic  passphrase
  -q, --quiet                Reduces all log output except errors
  -r, --raw                  Skip PONTIFEX MESSAGE frame. (-e / -d)
  -v, --verbose              Increases verbosity (up to '-vv')
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```


## Dependencies

* For enoch itself:
    * [GNU argp](https://www.gnu.org/software/libc/manual/html_node/Argp.html)
* For testing:
    * [CUnit](http://cunit.sourceforge.net)
    * [Valgrind](https://valgrind.org)

## Build

Run `make`. This will build and execute the unit tests as well.
To execute the Valgrind tests as well, run `make valgrind`
To build enoch only, run `make enoch`.

