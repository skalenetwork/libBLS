#pragma once

#include <cstdint>

namespace libBLS {

/**
 * @brief Complete threshold-encryption wire/derivation profile.
 *
 * The profile selects the threshold-encryption masking rules and, for
 * deterministic encryption, the deterministic AES-GCM IV derivation rules.
 * Callers should select this profile instead of selecting the TE and AES
 * versions independently.
 */
enum class EncryptionVersion : uint8_t {
    /// Legacy TE masking and legacy deterministic AES-GCM IV derivation.
    V0 = 0x00,
    /// 256-bit TE masking and AAD-bound deterministic AES-GCM IV derivation.
    V1 = 0x01,
};

static constexpr EncryptionVersion LATEST_ENCRYPTION_VERSION = EncryptionVersion::V1;

}  // namespace libBLS
