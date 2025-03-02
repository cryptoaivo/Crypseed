#include "utils.h"
#include "bip39.h"
#include <iostream>
#include <sstream>
#include <algorithm>

namespace utils {

    // Parse GPU choice from user input (e.g., "0", "0,1", "all")
    std::vector<int> parseGPUChoice(const std::string& choice, int gpuCount) {
        std::vector<int> selectedGPUs;
        if (choice == "all") {
            for (int i = 0; i < gpuCount; ++i) {
                selectedGPUs.push_back(i);
            }
        } else {
            std::stringstream ss(choice);
            std::string token;
            while (std::getline(ss, token, ',')) {
                token.erase(0, token.find_first_not_of(" "));
                token.erase(token.find_last_not_of(" ") + 1);
                try {
                    int idx = std::stoi(token);
                    if (idx >= 0 && idx < gpuCount) {
                        selectedGPUs.push_back(idx);
                    }
                } catch (const std::exception&) {
                    // Ignore invalid entries silently
                }
            }
        }
        return selectedGPUs;
    }

    // Get seed phrase input from user (ordered, unordered, or mixed)
    SeedPhraseInput getSeedPhraseInput() {
        SeedPhraseInput input;
        char hasKnownWords;
        std::cout << "Do you know any seed phrase words? (y/n): ";
        std::cin >> hasKnownWords;
        std::cin.ignore();

        if (tolower(hasKnownWords) != 'y') {
            return input;
        }

        char orderChoice;
        std::cout << "Do you know the order of the words? (y/n/mixed): ";
        std::cin >> orderChoice;
        std::cin.ignore();

        std::string userInput;
        std::cout << "Enter words:\n";
        std::cout << "- With order: e.g., 'abandon 1, zoo 12'\n";
        std::cout << "- Without order: e.g., 'zoo, abandon'\n";
        std::cout << "- Mixed: e.g., 'abandon 1, zoo 12, ball, hand'\n";
        std::cout << "Input: ";
        std::getline(std::cin, userInput);

        std::stringstream ss(userInput);
        std::string token;
        while (std::getline(ss, token, ',')) {
            token.erase(0, token.find_first_not_of(" ")); // Trim leading spaces
            token.erase(token.find_last_not_of(" ") + 1); // Trim trailing spaces
            
            std::stringstream word_ss(token);
            std::string word;
            int pos = 0;
            word_ss >> word;
            if (word_ss >> pos) {
                // Word with position (e.g., "abandon 1")
                if (pos >= 1 && pos <= 12 && std::find(bip39::wordlist.begin(), bip39::wordlist.end(), word) != bip39::wordlist.end()) {
                    input.words.push_back(SeedWord(word, pos));
                } else {
                    std::cout << "Warning: Invalid position or word '" << word << " " << pos << "' ignored.\n";
                }
            } else {
                // Word without position (e.g., "zoo")
                if (std::find(bip39::wordlist.begin(), bip39::wordlist.end(), word) != bip39::wordlist.end()) {
                    input.words.push_back(SeedWord(word, 0));
                } else {
                    std::cout << "Warning: Invalid BIP-39 word '" << word << "' ignored.\n";
                }
            }
        }

        return input;
    }

} // namespace utils