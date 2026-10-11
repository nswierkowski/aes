#pragma once
#include "types.hpp"
#include <vector>
#include "padding.hpp"

namespace ECB {

    template<typename Cipher>
    class ECBMode {
        
        public:
        explicit ECBMode(const Cipher& cipher): cipher(cipher) {}

        std::vector<byte> encrypt(std::vector<byte>& plain_text) {
            padding::add_padding(plain_text);

            std::vector<byte> encrypted_text;
            encrypted_text.reserve(plain_text.size());
            for (std::size_t i = 0; i < plain_text.size(); i += BLOCK_SIZE) {
                
                Block block;
                for (std::size_t j = 0; j < BLOCK_SIZE; j++) {
                    block[j] = plain_text.at(i+j);
                }

                Block encrypted_block = cipher.encrypt(block);
                encrypted_text.insert(encrypted_text.end(), encrypted_block.begin(), encrypted_block.end());
            }
            
            return encrypted_text;
        }

        std::vector<byte> decrypt(std::vector<byte>& encrypted_text)
        {
            std::vector<byte> plain_text;
            plain_text.reserve(encrypted_text.size());
            for (std::size_t i = 0; i < encrypted_text.size(); i += BLOCK_SIZE) {
                
                Block block;
                for (std::size_t j = 0; j < BLOCK_SIZE; j++) {
                    block[j] = encrypted_text.at(i+j);
                }

                Block decrypted_block = cipher.decrypt(block);
                plain_text.insert(plain_text.end(), decrypted_block.begin(), decrypted_block.end());
            }

            padding::remove_padding(plain_text);

            return plain_text;
        }

        private:
            Cipher cipher;
    };
}