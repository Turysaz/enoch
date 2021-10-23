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
> # encrypt:
> enoch -p cryptonomicon | tee out.txt
solitaire
^D
-----BEGIN PONTIFEX MESSAGE-----
KIRAK SFJAN 
-----END PONTIFEX MESSAGE-----

> # decrypt:
> enoch -d -p cryptonomicon -i out.txt
SOLITAIREX
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

