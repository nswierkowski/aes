#pragma once
#include "types.hpp"
#include <vector>
#include "padding.hpp"

namespace CBC {

    template<typename Cipher>
    class CBCMode {
        
        public:
        explicit CBCMode(const Cipher& cipher): cipher(cipher) {}

        std::vector<byte> encrypt(std::vector<byte>& plain_text, Block& vi) {
            padding::add_padding(plain_text);

            std::vector<byte> encrypted_text;
            encrypted_text.reserve(plain_text.size() + BLOCK_SIZE);

            encrypted_text.insert(encrypted_text.end(), vi.begin(), vi.end());
            Block vector_for_xor = vi; 
            for (std::size_t i = 0; i < plain_text.size(); i += BLOCK_SIZE) {
                
                Block block;
                for (std::size_t j = 0; j < BLOCK_SIZE; j++) {
                    block[j] = plain_text.at(i+j) ^ vector_for_xor[j];
                }

                Block encrypted_block = cipher.encrypt(block);
                encrypted_text.insert(encrypted_text.end(), encrypted_block.begin(), encrypted_block.end());
                vector_for_xor = encrypted_block;
            }
            
            return encrypted_text;
        }

        std::vector<byte> decrypt(std::vector<byte>& encrypted_text)
        {
            std::vector<byte> plain_text;
            plain_text.reserve(encrypted_text.size() - BLOCK_SIZE);

            Block previous_cipher_block; 
            for (std::size_t i = 0; i < BLOCK_SIZE; i++) {
                previous_cipher_block[i] = encrypted_text.at(i);
            }

            for (std::size_t i = BLOCK_SIZE; i < encrypted_text.size(); i += BLOCK_SIZE) {
                
                Block block;
                for (std::size_t j = 0; j < BLOCK_SIZE; j++) {
                    block[j] = encrypted_text.at(i+j);
                }

                Block decrypted_block = cipher.decrypt(block);
                for (std::size_t j = 0; j < BLOCK_SIZE; j++) {
                    decrypted_block[j] ^= previous_cipher_block[j];
                }
                
                plain_text.insert(plain_text.end(), decrypted_block.begin(), decrypted_block.end());
                previous_cipher_block = block;
            }

            padding::remove_padding(plain_text);

            return plain_text;
        }

        private:
            Cipher cipher;
    };
}