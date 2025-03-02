#pragma once
#include <vector>
#include <string>

namespace utils {
    struct SeedWord {
        std::string word;
        int position; // 0 if unknown, 1-12 if known
        SeedWord(std::string w = "", int p = 0) : word(w), position(p) {}
    };

    struct SeedPhraseInput {
        std::vector<SeedWord> words;
    };

    std::vector<int> parseGPUChoice(const std::string& choice, int gpuCount);
    SeedPhraseInput getSeedPhraseInput();
}