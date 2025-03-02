#pragma once
#include "utils.h"
#include <vector>
#include <string>

namespace gpu_manager {
    std::vector<std::string> detectGPUs();
    void runCracker(const std::string& targetAddress, const std::vector<int>& gpuIds, const utils::SeedPhraseInput& input);
}