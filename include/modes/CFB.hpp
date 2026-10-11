#pragma once
#include "types.hpp"
#include <vector>
#include "padding.hpp"

namespace CFB {

    template<typename Cipher>
    class CFBMode {
        
        public:
        explicit CFBMode(const Cipher& cipher): cipher(cipher) {}

        std::vector<byte> encrypt(std::vector<byte>& plain_text, Block& vi) {

            std::vector<byte> encrypted_text;
            encrypted_text.reserve(plain_text.size() + BLOCK_SIZE);

            encrypted_text.insert(encrypted_text.end(), vi.begin(), vi.end());
            Block previous_block = cipher.encrypt(vi); 
            for (std::size_t i = 0; i < plain_text.size(); i += BLOCK_SIZE) {
                std::size_t current_block_size = std::min(BLOCK_SIZE, plain_text.size() - i);
                
                Block block{};
                for (std::size_t j = 0; j < current_block_size; j++) {
                    block[j] = plain_text.at(i+j) ^ previous_block[j];
                }

                encrypted_text.insert(encrypted_text.end(), block.begin(), block.begin() + current_block_size);
                previous_block = cipher.encrypt(block);
            }
            
            return encrypted_text;
        }

        std::vector<byte> decrypt(std::vector<byte>& encrypted_text)
        {
            if (encrypted_text.size() <= BLOCK_SIZE) {
                return {};
            }

            std::vector<byte> plain_text;
            plain_text.reserve(encrypted_text.size() - BLOCK_SIZE);

            Block previous_cipher_block; 
            for (std::size_t i = 0; i < BLOCK_SIZE; i++) {
                previous_cipher_block[i] = encrypted_text.at(i);
            }
            previous_cipher_block = cipher.encrypt(previous_cipher_block);
            for (std::size_t i = BLOCK_SIZE; i < encrypted_text.size(); i += BLOCK_SIZE) {
                std::size_t current_block_size = std::min(BLOCK_SIZE, encrypted_text.size() - i);

                Block plain_block{};
                Block current_cipher_block{}; 
                for (std::size_t j = 0; j < current_block_size; j++) {
                    current_cipher_block[j] = encrypted_text.at(i+j); 
                    plain_block[j] = current_cipher_block[j] ^ previous_cipher_block[j];
                }
                
                plain_text.insert(plain_text.end(), plain_block.begin(), plain_block.begin() + current_block_size);
                previous_cipher_block = cipher.encrypt(current_cipher_block);
            }

            return plain_text;
        }

        private:
            Cipher cipher;
    };
}