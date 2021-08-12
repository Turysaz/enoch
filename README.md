# Shaftoe

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

## Example

```bash
> # encrypt:
> shaftoe -p cryptonomicon --raw | tee out.txt
solitaire
EOF
KIRAK SFJAN 

> # decrypt:
> shaftoe -d -p cryptonomicon -i out.txt
SOLITAIREX
```

## Dependencies

* [GNU argp](https://www.gnu.org/software/libc/manual/html_node/Argp.html)
* [CUnit](http://cunit.sourceforge.net)

## Build

Run `make`. This will build and execute the unit tests as well.

To build shaftoe only, run `make shaftoe`.

