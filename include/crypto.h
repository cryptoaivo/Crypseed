#pragma once
#include "bip39.h"
#include <string>
#include <vector>

namespace crypto {
    std::string deriveAddress(const std::vector<std::string>& mnemonic);
}