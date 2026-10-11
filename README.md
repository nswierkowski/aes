# AES, Block Ciphers
C++20 implementation of the AES block cipher supporting 128-bit, 192-bit, and 256-bit key sizes along with standard modes of operation including ECB, CBC, CFB, and OFB. The application features a command-line interface powered by CLI11 with automatic dependency resolution through CMake FetchContent.

Building
Building the project requires a C++20 compliant compiler and CMake 3.16 or newer. All external dependencies are downloaded and configured automatically during the build step.

```{Bash}
cmake -B build
cmake --build build
```
Usage
The generated binary provides subcommands for file encryption (enc) and decryption (dec). Key sizes are detected automatically from the hex string length, accepting 32 characters for AES-128, 48 characters for AES-192, and 64 characters for AES-256. Supported cipher modes are specified using the mode flag as ecb, cbc, cfb, or ofb. For modes requiring an initialization vector, a 32-character hex IV can be provided, or one will be generated automatically during encryption.

Encrypting a file using AES-256 in CBC mode:

```{Bash}
./build/aes_app enc -m cbc -k 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 -i input.txt -o output.enc
```
Decrypting the file back to plaintext using the same key and mode:

```{Bash}
./build/aes_app dec -m cbc -k 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 -i output.enc -o decrypted.txt
```
Have a nice day