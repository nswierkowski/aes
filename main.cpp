#include <iostream>
#include <iomanip>
#include "aes.hpp"

void print_block(const std::string &label, const AES::Block &block)
{
    std::cout << label << ": ";
    for (AES::byte b : block)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b) << " ";
    }
    std::cout << std::dec << "\n";
}

int main()
{
    AES::AES128::Key key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    AES::Block plaintext = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    AES::AES128 aes(key);

    AES::Block ciphertext = aes.encrypt(plaintext);
    AES::Block decrypted  = aes.decrypt(ciphertext);

    print_block("Key       ", key);
    print_block("Plaintext ", plaintext);
    print_block("Ciphertext", ciphertext);
    print_block("Decrypted ", decrypted);

    return 0;
}