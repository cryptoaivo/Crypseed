#include "bip39.h"
#include "crypto.h"
#include "gpu_manager.h"
#include "utils.h"
#include <iostream>
#include <vector>
#include <string>

int main() {
    std::cout << "Welcome to CrypSeed - Seed Phrase Cracker\n";
    std::cout << "=========================================\n";

    // Step 1: Get target address
    std::string targetAddress;
    std::cout << "Enter the target wallet address: ";
    std::getline(std::cin, targetAddress);

    // Step 2: Detect and select GPUs
    std::vector<std::string> gpuNames = gpu_manager::detectGPUs();
    if (gpuNames.empty()) {
        std::cout << "No CUDA-capable GPUs detected. Exiting.\n";
        return 1;
    }
    std::cout << "Detected " << gpuNames.size() << " GPU(s):\n";
    for (size_t i = 0; i < gpuNames.size(); ++i) {
        std::cout << "[" << i << "] " << gpuNames[i] << "\n";
    }
    std::string gpuChoice;
    std::cout << "Select GPU(s) to use (e.g., '0', '0,1', 'all'): ";
    std::getline(std::cin, gpuChoice);
    std::vector<int> selectedGPUs = utils::parseGPUChoice(gpuChoice, static_cast<int>(gpuNames.size()));
    if (selectedGPUs.empty()) {
        std::cout << "No valid GPUs selected. Exiting.\n";
        return 1;
    }
    std::cout << "Using GPU(s): ";
    for (int idx : selectedGPUs) std::cout << gpuNames[idx] << " ";
    std::cout << "\n";

    // Step 3: Get seed phrase input
    utils::SeedPhraseInput seedInput = utils::getSeedPhraseInput();

    // Prepare seed template and unordered words for display and cracking
    std::vector<std::string> seedTemplate(12, "[unknown]");
    std::vector<std::string> unorderedWords;
    for (const auto& kw : seedInput.words) {
        if (kw.position > 0 && seedTemplate[kw.position - 1] == "[unknown]") {
            seedTemplate[kw.position - 1] = kw.word;
        } else if (kw.position == 0) {
            unorderedWords.push_back(kw.word);
        } else {
            std::cout << "Warning: Position " << kw.position << " already filled or invalid.\n";
        }
    }
    std::cout << "Seed phrase template:\n";
    for (int i = 0; i < 12; ++i) {
        std::cout << (i + 1) << ": " << seedTemplate[i] << "\n";
    }
    if (!unorderedWords.empty()) {
        std::cout << "Unordered words to permute: ";
        for (const auto& w : unorderedWords) std::cout << w << " ";
        std::cout << "\n";
    }

    // Step 4: Run the cracker on selected GPUs
    gpu_manager::runCracker(targetAddress, selectedGPUs, seedInput);

    std::cout << "Cracking complete (demo mode).\n";
    std::cout << "Press Enter to exit.\n";
    std::cin.get();
    return 0;
}