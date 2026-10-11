#include <CLI/CLI.hpp>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <span>
#include <stdexcept>

#include "aes.hpp"
#include "modes/ECB.hpp"
#include "modes/CBC.hpp"
#include "modes/CFB.hpp"
#include "modes/OFB.hpp"
#include "utils/random_vi.hpp"
#include "utils/binary_io.hpp"

std::vector<byte> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Could not open input file: " + path.string());
    return std::vector<byte>((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path& path, std::span<const byte> data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Could not open output file: " + path.string());
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

template <std::size_t KeySize>
std::vector<byte> process_cipher(bool is_encrypt, 
                                 const std::array<byte, KeySize>& key, 
                                 const std::string& mode_str, 
                                 std::vector<byte>& input_data, 
                                 const Block& iv) {
    AES::AES<KeySize> aes(key);

    if (is_encrypt) {
        if (mode_str == "ecb") return ECB::ECBMode(aes).encrypt(input_data);
        if (mode_str == "cbc") return CBC::CBCMode(aes).encrypt(input_data, iv);
        if (mode_str == "cfb") return CFB::CFBMode(aes).encrypt(input_data, iv);
        if (mode_str == "ofb") return OFB::OFBMode(aes).encrypt(input_data, iv);
    } else {
        if (mode_str == "ecb") return ECB::ECBMode(aes).decrypt(input_data);
        if (mode_str == "cbc") return CBC::CBCMode(aes).decrypt(input_data);
        if (mode_str == "cfb") return CFB::CFBMode(aes).decrypt(input_data);
        if (mode_str == "ofb") return OFB::OFBMode(aes).decrypt(input_data);
    }

    throw std::invalid_argument("Unknown cipher mode: " + mode_str);
}

int main(int argc, char** argv) {
    CLI::App app{"AES Block Cipher CLI Tool (AES-128, AES-192, AES-256)"};
    app.require_subcommand(1);

    std::string mode_str = "cbc";
    std::string key_hex;
    std::string iv_hex;
    std::string input_path;
    std::string output_path;

    const std::string key_desc = "Key in Hex: 32 chars (128-bit), 48 chars (192-bit), or 64 chars (256-bit)";

    auto enc = app.add_subcommand("enc", "Encrypt an input file");
    enc->add_option("-m,--mode", mode_str, "Cipher mode: ecb, cbc, cfb, ofb")->capture_default_str();
    enc->add_option("-k,--key", key_hex, key_desc)->required();
    enc->add_option("-v,--iv", iv_hex, "128-bit IV in Hex (32 chars, auto-generated if omitted)");
    enc->add_option("-i,--in", input_path, "Input file path")->required()->check(CLI::ExistingFile);
    enc->add_option("-o,--out", output_path, "Output file path")->required();

    auto dec = app.add_subcommand("dec", "Decrypt an input file");
    dec->add_option("-m,--mode", mode_str, "Cipher mode: ecb, cbc, cfb, ofb")->capture_default_str();
    dec->add_option("-k,--key", key_hex, key_desc)->required();
    dec->add_option("-i,--in", input_path, "Input file path")->required()->check(CLI::ExistingFile);
    dec->add_option("-o,--out", output_path, "Output file path")->required();

    CLI11_PARSE(app, argc, argv);

    try {
        bool is_encrypt = app.got_subcommand(enc);
        auto input_data = read_file(input_path);
        std::vector<byte> output_data;

        Block iv{};
        if (is_encrypt) {
            if (!iv_hex.empty()) {
                auto parsed_iv = binary_io::parse_hex<16>(iv_hex);
                if (!parsed_iv) {
                    std::cerr << "Error: IV must be a 32-character hex string (128 bits).\n";
                    return 1;
                }
                iv = *parsed_iv;
            } else {
                iv = random_vi::generate_random_vi();
            }
        }

        std::size_t key_len = key_hex.size();

        if (key_len == 32) {
            auto key = binary_io::parse_hex<16>(key_hex);
            if (!key) { std::cerr << "Error: Invalid hex format for key.\n"; return 1; }
            output_data = process_cipher<16>(is_encrypt, *key, mode_str, input_data, iv);

        } else if (key_len == 48) { 
            auto key = binary_io::parse_hex<24>(key_hex);
            if (!key) { std::cerr << "Error: Invalid hex format for key.\n"; return 1; }
            output_data = process_cipher<24>(is_encrypt, *key, mode_str, input_data, iv);

        } else if (key_len == 64) { 
            auto key = binary_io::parse_hex<32>(key_hex);
            if (!key) { std::cerr << "Error: Invalid hex format for key.\n"; return 1; }
            output_data = process_cipher<32>(is_encrypt, *key, mode_str, input_data, iv);

        } else {
            std::cerr << "Error: Key length must be 32 (128-bit), 48 (192-bit), or 64 (256-bit) hex characters.\n";
            return 1;
        }

        write_file(output_path, output_data);
        std::cout << "Operation completed successfully -> " << output_path << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Fatal Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}