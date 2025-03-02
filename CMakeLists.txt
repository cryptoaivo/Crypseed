cmake_minimum_required(VERSION 3.10)
project(CrypSeed CUDA CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find CUDA
find_package(CUDA REQUIRED)
if (NOT CUDA_FOUND)
    message(FATAL_ERROR "CUDA not found. Please install the CUDA Toolkit.")
endif()
include_directories(${CUDA_INCLUDE_DIRS})
link_directories(${CUDA_LIBRARY_DIRS})

# Find OpenSSL
find_package(OpenSSL REQUIRED)
if (NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL.")
endif()
include_directories(${OPENSSL_INCLUDE_DIR})

# Find libsecp256k1
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)
if (NOT SECP256K1_FOUND)
    message(FATAL_ERROR "libsecp256k1 not found. Please install libsecp256k1.")
endif()
include_directories(${SECP256K1_INCLUDE_DIRS})
link_directories(${SECP256K1_LIBRARY_DIRS})

# Include project headers
include_directories(${CMAKE_SOURCE_DIR}/include)

# Define source files
set(SOURCES
    src/main.cpp
    src/bip39.cpp
    src/crypto.cpp
    src/gpu_manager.cpp
    src/utils.cpp
)

# Define CUDA kernel files
set(CUDA_SOURCES
    kernels/crack_kernel.cu
)

# Add executable with CUDA support
cuda_add_executable(CrypSeed
    ${SOURCES}
    ${CUDA_SOURCES}
)

# Link libraries
target_link_libraries(CrypSeed
    ${CUDA_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SECP256K1_LIBRARIES}
)

# Enable separable compilation for CUDA
set_target_properties(CrypSeed PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

# Optional: Set output directory
set_target_properties(CrypSeed PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release"
)

# Print configuration details (optional)
message(STATUS "CUDA Include Dirs: ${CUDA_INCLUDE_DIRS}")
message(STATUS "CUDA Libraries: ${CUDA_LIBRARIES}")
message(STATUS "OpenSSL Include Dirs: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "libsecp256k1 Include Dirs: ${SECP256K1_INCLUDE_DIRS}")
message(STATUS "libsecp256k1 Libraries: ${SECP256K1_LIBRARIES}")