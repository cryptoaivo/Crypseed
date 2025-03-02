#include "gpu_manager.h"
#include "crypto.h"
#include "bip39.h"
#include <cuda_runtime.h>
#include <iostream>
#include <cstring>

namespace gpu_manager {

    std::vector<std::string> detectGPUs() {
        std::vector<std::string> gpuNames;
        int deviceCount = 0;
        cudaError_t err = cudaGetDeviceCount(&deviceCount);
        if (err != cudaSuccess || deviceCount == 0) {
            std::cout << "No CUDA-capable GPUs detected: " << cudaGetErrorString(err) << "\n";
            return gpuNames;
        }
        for (int i = 0; i < deviceCount; ++i) {
            cudaDeviceProp prop;
            cudaGetDeviceProperties(&prop, i);
            gpuNames.push_back(std::string(prop.name));
        }
        return gpuNames;
    }

    // CUDA kernel declaration (defined in crack_kernel.cu)
    __global__ void crackKernel(
        const char* wordlist, int wordlistSize, const char* targetAddress,
        const utils::SeedWord* knownWords, int knownCount,
        bool* found, char* result, int resultSize
    );

    void runCracker(const std::string& targetAddress, const std::vector<int>& gpuIds, const utils::SeedPhraseInput& input) {
        std::cout << "Cracking with " << gpuIds.size() << " GPU(s)...\n";

        // Prepare wordlist buffer (null-terminated strings)
        std::string wordlistBuffer;
        for (const auto& word : bip39::wordlist) {
            wordlistBuffer += word + "\0";
        }

        for (int gpuIdx : gpuIds) {
            cudaSetDevice(gpuIdx);
            cudaDeviceProp prop;
            cudaGetDeviceProperties(&prop, gpuIdx);
            std::cout << "Optimizing for " << prop.name << "...\n";

            // Allocate GPU memory
            char* d_wordlist;
            cudaMalloc(&d_wordlist, wordlistBuffer.size());
            cudaMemcpy(d_wordlist, wordlistBuffer.c_str(), wordlistBuffer.size(), cudaMemcpyHostToDevice);

            char* d_targetAddress;
            cudaMalloc(&d_targetAddress, targetAddress.size() + 1);
            cudaMemcpy(d_targetAddress, targetAddress.c_str(), targetAddress.size() + 1, cudaMemcpyHostToDevice);

            utils::SeedWord* d_knownWords;
            cudaMalloc(&d_knownWords, input.words.size() * sizeof(utils::SeedWord));
            cudaMemcpy(d_knownWords, input.words.data(), input.words.size() * sizeof(utils::SeedWord), cudaMemcpyHostToDevice);

            bool* d_found;
            cudaMalloc(&d_found, sizeof(bool));
            cudaMemset(d_found, 0, sizeof(bool));

            const int resultSize = 256; // Max size for mnemonic string
            char* d_result;
            cudaMalloc(&d_result, resultSize);

            // Calculate grid size (demo: small range; adjust for real brute-force)
            int threadsPerBlock = 256;
            int blocks = 1024; // Larger grid for real cracking, e.g., 2048 * 2048 for 2 unknown words
            crackKernel<<<blocks, threadsPerBlock>>>(
                d_wordlist, bip39::wordlist.size(), d_targetAddress,
                d_knownWords, input.words.size(), d_found, d_result, resultSize
            );

            cudaError_t err = cudaGetLastError();
            if (err != cudaSuccess) {
                std::cout << "Kernel launch failed on GPU " << gpuIdx << ": " << cudaGetErrorString(err) << "\n";
            }

            // Synchronize and check result
            cudaDeviceSynchronize();
            bool found;
            char result[resultSize];
            cudaMemcpy(&found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
            if (found) {
                cudaMemcpy(result, d_result, resultSize, cudaMemcpyDeviceToHost);
                std::cout << "GPU " << gpuIdx << " found seed phrase: " << result << "\n";
            } else {
                std::cout << "GPU " << gpuIdx << ": No match found in current range.\n";
            }

            // Cleanup
            cudaFree(d_wordlist);
            cudaFree(d_targetAddress);
            cudaFree(d_knownWords);
            cudaFree(d_found);
            cudaFree(d_result);
        }
    }

} // namespace gpu_manager