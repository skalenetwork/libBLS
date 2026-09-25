#pragma once

#include <cstdint>

namespace libBLS {

/**
 * @brief Format version for Threshold Encryption ciphertexts and ciphered keys.
 */
enum class TEVersion : uint8_t {
    /// V0: Legacy ASCII hex masking (128 bits entropy)
    V0 = 0x00,
    /// V1: 256-bit raw SHA256 bytes masking
    V1 = 0x01,
};

static constexpr TEVersion LATEST_TE_VERSION = TEVersion::V1;

}  // namespace libBLS
