#include "bip39.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <bitset>

namespace bip39 {

    // Load BIP-39 wordlist from file
    const std::vector<std::string> wordlist = []() {
        std::vector<std::string> wl;
        std::ifstream file("../resources/wordlist.txt");
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open wordlist.txt");
        }
        std::string word;
        while (std::getline(file, word)) {
            wl.push_back(word);
        }
        if (wl.size() != 2048) {
            throw std::runtime_error("Wordlist must contain exactly 2048 words");
        }
        return wl;
    }();

    // Helper: Convert bytes to binary string
    static std::string bytesToBinary(const std::vector<unsigned char>& bytes) {
        std::string binary;
        for (unsigned char byte : bytes) {
            binary += std::bitset<8>(byte).to_string();
        }
        return binary;
    }

    // Helper: Convert binary string to word indices
    static std::vector<size_t> binaryToIndices(const std::string& binary, size_t entropyBits, size_t checksumBits) {
        std::vector<size_t> indices;
        size_t totalBits = entropyBits + checksumBits;
        for (size_t i = 0; i < totalBits; i += 11) {
            std::string chunk = binary.substr(i, 11);
            size_t index = std::stoul(chunk, nullptr, 2);
            indices.push_back(index);
        }
        return indices;
    }

    std::vector<std::string> entropyToMnemonic(const std::vector<unsigned char>& entropy) {
        if (entropy.size() != 16 && entropy.size() != 20 && entropy.size() != 24 && entropy.size() != 28 && entropy.size() != 32) {
            throw std::invalid_argument("Entropy must be 128, 160, 192, 224, or 256 bits (16-32 bytes)");
        }

        size_t entropyBits = entropy.size() * 8;
        size_t checksumBits = entropyBits / 32;

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(&entropy[0], entropy.size(), hash);

        std::string binaryEntropy = bytesToBinary(entropy);
        std::string binaryChecksum = bytesToBinary(std::vector<unsigned char>(hash, hash + 1)).substr(0, checksumBits);
        std::string binary = binaryEntropy + binaryChecksum;

        std::vector<size_t> indices = binaryToIndices(binary, entropyBits, checksumBits);
        std::vector<std::string> mnemonic;
        for (size_t index : indices) {
            mnemonic.push_back(wordlist[index]);
        }
        return mnemonic;
    }

    bool isValidMnemonic(const std::vector<std::string>& mnemonic) {
        if (mnemonic.size() != 12 && mnemonic.size() != 15 && mnemonic.size() != 18 && mnemonic.size() != 21 && mnemonic.size() != 24) {
            return false;
        }

        std::vector<size_t> indices;
        for (const auto& word : mnemonic) {
            auto it = std::find(wordlist.begin(), wordlist.end(), word);
            if (it == wordlist.end()) return false;
            indices.push_back(std::distance(wordlist.begin(), it));
        }

        std::string binary;
        for (size_t index : indices) {
            binary += std::bitset<11>(index).to_string();
        }

        size_t entropyBits = (mnemonic.size() * 11) - (mnemonic.size() / 3);
        size_t checksumBits = mnemonic.size() / 3;
        std::string entropyBinary = binary.substr(0, entropyBits);
        std::string checksumBinary = binary.substr(entropyBits, checksumBits);

        std::vector<unsigned char> entropy;
        for (size_t i = 0; i < entropyBits; i += 8) {
            std::string byteStr = entropyBinary.substr(i, 8);
            entropy.push_back(static_cast<unsigned char>(std::stoul(byteStr, nullptr, 2)));
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(entropy.data(), entropy.size(), hash);
        std::string computedChecksum = bytesToBinary(std::vector<unsigned char>(hash, hash + 1)).substr(0, checksumBits);

        return checksumBinary == computedChecksum;
    }

    std::vector<unsigned char> mnemonicToSeed(const std::vector<std::string>& mnemonic, const std::string& passphrase) {
        if (!isValidMnemonic(mnemonic)) {
            throw std::invalid_argument("Invalid mnemonic phrase");
        }

        std::string mnemonicStr = mnemonicToString(mnemonic);
        std::string salt = "mnemonic" + passphrase;

        std::vector<unsigned char> seed(64); // 512-bit seed
        if (PKCS5_PBKDF2_HMAC(
                mnemonicStr.c_str(), mnemonicStr.size(),
                reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                2048, EVP_sha512(),
                seed.size(), seed.data()) != 1) {
            throw std::runtime_error("PBKDF2 derivation failed");
        }
        return seed;
    }

    std::string mnemonicToString(const std::vector<std::string>& mnemonic) {
        std::stringstream ss;
        for (size_t i = 0; i < mnemonic.size(); ++i) {
            ss << mnemonic[i];
            if (i < mnemonic.size() - 1) ss << " ";
        }
        return ss.str();
    }

} // namespace bip39