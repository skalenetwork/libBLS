#pragma once

#include "backends/interface/field/FqElement.hpp"
#include "tools/utils.h"
#include <cstring>
#include <functional>

namespace libBLS::algebra {

template < class Derived, size_t NUM_AFFINE_COMPONENTS, size_t NUM_PROJECTIVE_COMPONENTS >
class PointSerializer {
    void forEachAffineComponent(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const {
        static_cast< Derived const* >( this )->forEachAffineComponentImpl(
            std::forward< const std::function< void( const FqElement&, size_t i ) >& >( fn ) );
    }

    void forEachProjectiveComponent(
        const std::function< void( const FqElement&, size_t i ) >& fn ) const {
        static_cast< Derived const* >( this )->forEachProjectiveComponentImpl(
            std::forward< const std::function< void( const FqElement&, size_t i ) >& >( fn ) );
    }

public:
    // ----------------------- Byte Serializations ----------------------- //

    std::array< uint8_t, NUM_AFFINE_COMPONENTS * FqElement::SIZE_BYTES > toByteArray() const {
        std::array< uint8_t, NUM_AFFINE_COMPONENTS * FqElement::SIZE_BYTES > out{};
        uint8_t* p = out.data();
        forEachAffineComponent( [&]( const FqElement& c, size_t ) {
            auto b = c.toByteArray();
            std::memcpy( p, b.data(), b.size() );
            p += b.size();
        } );
        return out;
    }

    // Byte serialization with no intermediate copies
    std::vector< uint8_t > toByteVector() const {
        std::vector< uint8_t > out;
        out.reserve( NUM_AFFINE_COMPONENTS * FqElement::SIZE_BYTES );
        forEachAffineComponent( [&]( const FqElement& c, size_t ) {
            auto b = c.toByteArray();
            out.insert( out.end(), b.begin(), b.end() );
        } );
        return out;
    }

    // ----------------------- String Serializations ----------------------- //

    std::string toString( Base base ) const {
        std::string out;
        if ( base == libBLS::Base::HEXA ) {
            // HEXA: concatenate fixed-width (64 char) hex strings
            forEachAffineComponent(
                [&]( const FqElement& c, size_t ) { out += c.toString( base ); } );
        } else {
            // DEC: join with colon delimiter (variable length decimal strings)
            forEachAffineComponent( [&]( const FqElement& c, size_t i ) {
                if ( i > 0 )
                    out += ":";
                out += c.toString( base );
            } );
        }
        return out;
    }

    std::array< std::string, NUM_AFFINE_COMPONENTS > toStringArray( Base base ) const {
        std::array< std::string, NUM_AFFINE_COMPONENTS > out;
        forEachAffineComponent(
            [&]( const FqElement& c, size_t i ) { out.at( i ) = c.toString( base ); } );
        return out;
    }

    std::vector< std::string > toStringVector( Base base ) const {
        std::vector< std::string > out;
        out.reserve( NUM_AFFINE_COMPONENTS );
        forEachAffineComponent(
            [&]( const FqElement& c, size_t ) { out.push_back( c.toString( base ) ); } );
        return out;
    }

    std::array< std::string, NUM_PROJECTIVE_COMPONENTS > toStringArrayProjective(
        Base base ) const {
        std::array< std::string, NUM_PROJECTIVE_COMPONENTS > out;
        forEachProjectiveComponent(
            [&]( const FqElement& c, size_t i ) { out.at( i ) = c.toString( base ); } );
        return out;
    }
};

}  // namespace libBLS::algebra