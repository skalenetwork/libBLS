#pragma once
#include "backends/algebra_types.hpp"
#include "backends/interface/curve_contract_altbn128.hpp"
#include "tools/utils.h"
#include <cstring>
#include <mcl/bn.hpp>


namespace libBLS::algebra {


inline int toIoBase( Base base ) {
    return (base == Base::DEC) ? 10 : 16;
}

/// Reduces a string representing an integer in the given base mod M_dec
/// and returns the result as a decimal string
inline std::string reduce_mod(std::string_view s, int base, std::string_view M_dec) {
    mpz_class z;
    z.set_str(s.data(), base);
    static thread_local mpz_class M;
    M.set_str(std::string(M_dec).c_str(), 10);
    z %= M;
    return z.get_str(10);                     // canonical decimal
}

/// @brief  Try to set the field element from the given string and base.
///         If the string is out of range, it will be reduced mod p.
/// @param x field element to set
/// @param str string representing the integer
/// @param base base of the integer representation
template < typename T>
inline void trySettingFieldWithString(T& x, const std::string& str, Base base) {
    try {
        // If you want to accept "0x" for HEXA, add mcl::IoPrefix:
        // const int io = (base == Base::DEC) ? mcl::IoDec : (mcl::IoHex | mcl::IoPrefix);
        x.setStr(str, toIoBase(base));
    } catch (const std::exception& e) {
        
        // string not in range - need to reduce mod p
        std::string reduced = reduce_mod(str, toIoBase(base), AltBn128Contract::p_dec);
        try {
            x.setStr(reduced, toIoBase(base));
        } catch (const std::exception& e) {
            THROW(e.what());
        }
    }
}

template< class T >
std::array<uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES> fieldElementToByteArray( const T& element ) {
    std::array<uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES> out{};

    std::string s = element.getStr(10); // base 10 decimal string
    mpz_class t;
    if (mpz_set_str(t.get_mpz_t(), s.c_str(), 10) != 0) {
        THROW("mpz_set_str failed");
    }

    size_t bit_len = mpz_sizeinbase(t.get_mpz_t(), 2);
    size_t byte_count = std::max<size_t>(1, (bit_len + 7) / 8);

    // write into the least-significant end (left-pad to fixed width)
    mpz_export(out.data() + (MAX_FIELD_ELEMENT_SIZE_BYTES - byte_count),
               nullptr,
               /*order*/ 1, /*size*/ 1, /*endian*/ 0, /*nails*/ 0,
               t.get_mpz_t());
    return out;
}

template < class T >
std::vector< uint8_t > fieldElementToBytes( const T& field_elem ) {
    std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES > bytes =
        fieldElementToByteArray( field_elem );
    std::vector< uint8_t > bytesVec( bytes.begin(), bytes.end() );
    return bytesVec;
}

// Convert a 32-byte array back to a algebra::FqElement or FrScalar element
template < class T >
T bytesToFieldElement( const std::array< uint8_t, MAX_FIELD_ELEMENT_SIZE_BYTES >& byte_array ) {
    T x;
    if (x.deserialize(byte_array.data(), byte_array.size()) == 0) {
        // TODO - exception needs better name - isNotWellFormed is misleading
        throw ThresholdUtils::IsNotWellFormed("FqElement::fromBytes: deserialization failed");
    }
    return x;
}

// Converts the first 32 bytes from the vector into a field element
template < class T >
T bytesToFieldElement( const std::vector< uint8_t >& byte_array ) {
    T x;
    if (x.deserialize(byte_array.data(), byte_array.size()) == 0) {
        // TODO - exception needs better name - isNotWellFormed is misleading
        throw ThresholdUtils::IsNotWellFormed("FqElement::fromBytes: deserialization failed");
    }
    return x;
}

enum class GroupPoint {
    G1,
    G2
};

// TODO - check if returns different random for each run
template < class T, GroupPoint GP >
T randomGroupPoint() {
    // create bytes from random Fr element
    std::array<uint8_t, 32> msg{};
    FrBackendType r;
    r.setByCSPRNG();
    size_t n = r.serialize(msg.data(), msg.size(), mcl::IoDec);
    // left-pad to 32 bytes in case serialize wrote fewer
    if (n < msg.size()) {
        std::memmove(msg.data() + (msg.size() - n), msg.data(), n);
        std::memset(msg.data(), 0, msg.size() - n);
    }

    if constexpr (GP == GroupPoint::G1) {
        G1BackendType P;
        mcl::hashAndMapToG1(P, msg.data(), msg.size());
        return T(P);
    }
    else {
        G2BackendType P;
        mcl::hashAndMapToG2(P, msg.data(), msg.size());
        return T(P);
    }
}

} // namespace libBLS::algebra