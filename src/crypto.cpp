#include "crypto.h"
#include "bip39.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>

namespace crypto {

    // Base58 encoding table
    static const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Convert bytes to Base58Check (used for Bitcoin addresses)
    std::string toBase58Check(const std::vector<unsigned char>& data) {
        std::vector<unsigned char> extended(data);
        // Append checksum (first 4 bytes of double SHA-256)
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), hash);
        SHA256(hash, SHA256_DIGEST_LENGTH, hash);
        extended.insert(extended.end(), hash, hash + 4);

        // Convert to base58
        std::string result;
        std::vector<unsigned char> digits(extended.size() * 138 / 100 + 1); // Rough estimate
        size_t digitslen = 1;
        for (size_t i = 0; i < extended.size(); i++) {
            unsigned int carry = extended[i];
            for (size_t j = 0; j < digitslen; j++) {
                carry += digits[j] << 8;
                digits[j] = carry % 58;
                carry /= 58;
            }
            while (carry) {
                digits[digitslen++] = carry % 58;
                carry /= 58;
            }
        }

        // Leading zeros
        for (const auto& byte : data) {
            if (byte != 0) break;
            result += BASE58_CHARS[0];
        }
        // Convert digits to characters
        for (size_t i = digitslen; i > 0; --i) {
            result += BASE58_CHARS[digits[i - 1]];
        }
        return result;
    }

    std::string deriveAddress(const std::vector<std::string>& mnemonic) {
        if (!bip39::isValidMnemonic(mnemonic)) {
            return ""; // Invalid mnemonic
        }

        // Step 1: Derive seed from mnemonic (BIP-39)
        std::vector<unsigned char> seed = bip39::mnemonicToSeed(mnemonic);

        // Step 2: Initialize secp256k1 context
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (!ctx) {
            throw std::runtime_error("Failed to create secp256k1 context");
        }

        // Step 3: Derive master private key (BIP-32 HD wallet)
        // Simplified: Use seed directly as private key for demo (in reality, use HMAC-SHA512 with "Bitcoin seed")
        unsigned char master_key[32];
        std::copy(seed.begin(), seed.begin() + 32, master_key); // Use first 32 bytes of seed

        // Step 4: Derive BIP-44 path m/44'/0'/0'/0/0 (Bitcoin, first account, first address)
        // For simplicity, we derive the key directly here (real BIP-32 would involve chain code and multiple derivations)
        secp256k1_keypair keypair;
        if (!secp256k1_keypair_create(ctx, &keypair, master_key)) {
            secp256k1_context_destroy(ctx);
            return ""; // Invalid private key
        }

        // Step 5: Get public key
        secp256k1_pubkey pubkey;
        if (!secp256k1_keypair_pub(ctx, &pubkey, &keypair)) {
            secp256k1_context_destroy(ctx);
            return "";
        }

        // Step 6: Serialize public key (compressed, 33 bytes)
        unsigned char pubkey_serialized[33];
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

        // Step 7: Compute Bitcoin address (SHA-256 -> RIPEMD-160 -> Base58Check)
        unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
        SHA256(pubkey_serialized, pubkey_len, sha256_hash);

        unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
        RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);

        // Prepend version byte (0x00 for Bitcoin mainnet)
        std::vector<unsigned char> address_data(1 + RIPEMD160_DIGEST_LENGTH);
        address_data[0] = 0x00; // Bitcoin mainnet
        std::copy(ripemd160_hash, ripemd160_hash + RIPEMD160_DIGEST_LENGTH, address_data.begin() + 1);

        // Step 8: Convert to Base58Check
        std::string address = toBase58Check(address_data);

        // Cleanup
        secp256k1_context_destroy(ctx);

        return address;
    }

} // namespace crypto