#include <padding.hpp>
#include <vector>
#include <types.hpp>
#include <cstdint>
#include <stdexcept>

namespace padding {

    void add_padding(std::vector<byte>& plain_text)
    {
        std::int8_t padding_elem = 16 - (plain_text.size() % 16);
  
        for (std::int8_t i = 0; i < padding_elem; i++) {
            plain_text.push_back(padding_elem);
        }
    }

    void remove_padding(std::vector<byte>& plain_text)
    {
        if (plain_text.empty()) return;

        byte padding_elem = plain_text.back();
        if (padding_elem <= 0 || padding_elem > 16 || padding_elem > plain_text.size()) {
            throw std::invalid_argument {"Padding element is not valid"};
        }

        for (std::size_t i = 0; i < padding_elem; ++i) {
            plain_text.pop_back();
        }
    }
}
