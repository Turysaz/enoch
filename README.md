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
* C89 compatible!

## Example

```bash
> # encrypt:
> pfx -p cryptonomicon --raw | tee out.txt
solitaire
EOF
KIRAK SFJAN 

> # decrypt:
> pfx -d -p cryptonomicon -i out.txt
SOLIT AIREX
```

## Dependencies

* [GNU argp](https://www.gnu.org/software/libc/manual/html_node/Argp.html)

## Build

Run `make`.

