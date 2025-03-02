#include <cuda_runtime.h>
#include "crypto.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

namespace {

    // Helper: Get word from wordlist buffer by index
    __device__ const char* getWord(const char* wordlist, int index) {
        const char* ptr = wordlist;
        for (int i = 0; i < index; ++i) {
            while (*ptr != '\0') ++ptr;
            ++ptr; // Skip null terminator
        }
        return ptr;
    }

    // Helper: Build mnemonic from known words and thread-specific guesses
    __device__ void buildMnemonic(
        char* mnemonic, int mnemonicSize,
        const utils::SeedWord* knownWords, int knownCount,
        const char* wordlist, int wordlistSize, int threadIdx
    ) {
        std::vector<std::string> phrase(12, "");
        int unorderedCount = 0;

        // Place known words with positions
        for (int i = 0; i < knownCount; ++i) {
            if (knownWords[i].position > 0 && knownWords[i].position <= 12) {
                phrase[knownWords[i].position - 1] = knownWords[i].word;
            } else if (knownWords[i].position == 0) {
                unorderedCount++;
            }
        }

        // Fill unordered words and unknowns using thread index
        int openSlots = 0;
        for (int i = 0; i < 12; ++i) {
            if (phrase[i].empty()) openSlots++;
        }

        if (openSlots > 0) {
            int idx = threadIdx;
            int unorderedFilled = 0;
            for (int i = 0; i < 12 && idx >= 0; ++i) {
                if (phrase[i].empty()) {
                    if (unorderedFilled < unorderedCount && i < knownCount) {
                        phrase[i] = knownWords[unorderedFilled].word; // Simplified permutation
                        unorderedFilled++;
                    } else {
                        int wordIdx = idx % wordlistSize;
                        phrase[i] = getWord(wordlist, wordIdx);
                        idx /= wordlistSize;
                    }
                }
            }
        }

        // Construct string
        mnemonic[0] = '\0';
        for (int i = 0; i < 12; ++i) {
            strncat(mnemonic, phrase[i].c_str(), mnemonicSize - strlen(mnemonic) - 1);
            if (i < 11) strncat(mnemonic, " ", mnemonicSize - strlen(mnemonic) - 1);
        }
    }

} // anonymous namespace

__global__ void crackKernel(
    const char* wordlist, int wordlistSize, const char* targetAddress,
    const utils::SeedWord* knownWords, int knownCount,
    bool* found, char* result, int resultSize
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (*found) return;

    // Generate candidate mnemonic
    char candidate[256];
    buildMnemonic(candidate, sizeof(candidate), knownWords, knownCount, wordlist, wordlistSize, idx);

    // Derive address and compare
    std::vector<std::string> mnemonicVec;
    char* token = strtok(candidate, " ");
    while (token != NULL) {
        mnemonicVec.push_back(std::string(token));
        token = strtok(NULL, " ");
    }

    std::string derivedAddress = crypto::deriveAddress(mnemonicVec);
    if (derivedAddress == targetAddress) {
        *found = true;
        strncpy(result, candidate, resultSize);
        result[resultSize - 1] = '\0'; // Ensure null-terminated
    }
}