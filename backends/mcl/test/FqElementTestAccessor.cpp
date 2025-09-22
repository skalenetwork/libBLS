#ifdef MCL

#include "backends/interface/test/FqElementTestAccessor.hpp"

namespace libBLS::algebra {

std::default_random_engine libBLS::algebra::FqElementTestAccessor::rand_gen(
    static_cast< unsigned int >( std::time( 0 ) ) );

FqElement FqElementTestAccessor::spoil( const FqElement& elem ) {
    FqBackendType elem_copy = elem.asBackendType();
    for ( ;; ) {
        // Serialize to bytes (Fp is 256-bit on BN254; 32 bytes is enough)
        uint8_t buf[FqElement::SIZE_BYTES];
        const size_t n = elem_copy.serialize( buf, sizeof( buf ) );
        // Choose one random bit across the serialized bytes
        const size_t bit = static_cast< size_t >( rand() ) % ( n * 8 );
        buf[bit / 8] ^= static_cast< uint8_t >( 1u << ( bit % 8 ) );

        FqBackendType spoiled;
        const size_t consumed = spoiled.deserialize( buf, n );

        if ( consumed == 0 ) {
            // Should not happen; if it does, retry
            continue;
        }

        if ( !spoiled.isZero() )
            return FqElement( spoiled );
        elem_copy = spoiled;
    }
}

}  // namespace libBLS::algebra

#endif  // MCL