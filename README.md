# SHA-1

 SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function which takes an input and produces a 160-bit (20-byte) hash value known as a message digest – typically rendered as a hexadecimal number, 40 digits long.

 This program implements the SHA-1 hashing algorithm in Python(CLI).

## Usage

```
usage: sha1.py [-h] [-f [file [file ...]]] [-s string]

optional arguments:
  -h, --help            show this help message and exit
  -f [file [file ...]], --file [file [file ...]]
                        Hash multiple files.
  -s string, --string string
                        Hash a string.
```

## References

- https://en.wikipedia.org/wiki/SHA-1
- https://www.metamorphosite.com/one-way-hash-encryption-sha1-data-software
- https://www.movable-type.co.uk/scripts/sha1.html

## TODO

-[ ] Write tests
-[ ] Input for multiple lines  support in windows

## License

[MIT](/LICENSE) License