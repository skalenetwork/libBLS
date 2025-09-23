/*
  Copyright (C) 2018-2019 SKALE Labs

  This file is part of libBLS.

  libBLS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libBLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with libBLS. If not, see <https://www.gnu.org/licenses/>.

  @file unit_tests_backend.cpp
  @author Sidnei Teixeira
  @date 2025
*/

#include <array>
#include <iostream>
#include <random>
#include <string>

#include <backends/algebra.hpp>
#include <backends/interface/functions.hpp>

#define BOOST_TEST_MODULE
#include <boost/test/included/unit_test.hpp>

using namespace libBLS::algebra;

// --- Deterministic RNG for reproducibility
static std::mt19937_64 Rng{ 0xB17E };

// Helper: make small random u64 (always < p) so constructors from uint64 are safe
static inline uint64_t rnd64() {
    return Rng();
}

// Test fixture to initialize the curve
struct BackendTestFixture {
    BackendTestFixture() { initCurve(); }
};

struct AlgebraDefaults {
    // Construct after BackendInit has run
    AlgebraDefaults() {
        std::array< std::string, G1Point::NUM_COMPONENTS_AFFINE > g1_str = {
            "17567712797424133172049016516177362576922732140972915262580733753509134091521",
            "22316455450998987136923191512030781530286773783910397683738508477890718687863"
        };
        g1_1 = G1Point::fromString( g1_str, Base::DEC );

        std::array< std::string, G1Point::NUM_COMPONENTS_AFFINE > g1_str_2 = {
            "17940658061935524123227685660839814585701462921639571639526763207225367528219",
            "13090417896243295126411982315888679183507640646580935511751213208768591653001"
        };
        g1_2 = G1Point::fromString( g1_str_2, Base::DEC );

        std::array< std::string, G2Point::NUM_COMPONENTS_AFFINE > g2_str = {
            "11917832168498262938884413573890421434994378528794298199004954141363400352994",
            "21139436732076230933827439810483559357168042121256448652065988327985214618333",
            "377364548531188984329919374389108487980775084497423006037040097374076740300",
            "11524576525234332095483297455554585123600030938937231901312802381582359613553"
        };

        g2_1 = G2Point::fromString( g2_str, Base::DEC );

        std::array< std::string, G2Point::NUM_COMPONENTS_AFFINE > g2_str_2 = {
            "15508737830296030553926253879648498286594773158202580462199525008975093104039",
            "6526968432579994218406902467738158465253621521328118845225721837547612307441",
            "2496503088736620033514232687175208734822481037774377849401811403832985035712",
            "15011347735313125592971842677123206425459968918092758693212514857970918021711"
        };

        g2_2 = G2Point::fromString( g2_str_2, Base::DEC );
    }

    G1Point g1_1, g1_2;
    G2Point g2_1, g2_2;
};

BOOST_TEST_GLOBAL_FIXTURE( BackendTestFixture );

BOOST_FIXTURE_TEST_SUITE( TestBackendTypes, AlgebraDefaults )

// ==================== FrScalar Tests ====================

BOOST_AUTO_TEST_CASE( FrScalar_Constructor_Default ) {
    FrScalar fr;
    BOOST_REQUIRE( fr.isZero() );
    BOOST_REQUIRE_EQUAL( fr.toString( Base::DEC ), "0" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Constructor_Size ) {
    FrScalar fr( 42 );
    BOOST_REQUIRE_EQUAL( fr.toString( Base::DEC ), "42" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Zero ) {
    FrScalar fr = FrScalar::zero();
    BOOST_REQUIRE( fr.isZero() );
    BOOST_REQUIRE_EQUAL( fr.toString( Base::DEC ), "0" );
}

BOOST_AUTO_TEST_CASE( FrScalar_One ) {
    FrScalar fr = FrScalar::one();
    BOOST_REQUIRE( fr.isOne() );
    BOOST_REQUIRE_EQUAL( fr.toString( Base::DEC ), "1" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Addition ) {
    FrScalar a( 10 );
    FrScalar b( 20 );
    FrScalar result = a + b;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "30" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Subtraction ) {
    FrScalar a( 30 );
    FrScalar b( 15 );
    FrScalar result = a - b;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "15" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Multiplication ) {
    FrScalar a( 7 );
    FrScalar b( 6 );
    FrScalar result = a * b;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "42" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Add_Sub_Mul_Distributivity ) {
    FrScalar a( rnd64() ), b( rnd64() ), c( rnd64() );
    // (a+b)*c == a*c + b*c
    BOOST_CHECK( ( a + b ) * c == a * c + b * c );
    // a + 0 = a; a*0 = 0; a*1 = a
    BOOST_CHECK( a + FrScalar::zero() == a );
    BOOST_CHECK( a * FrScalar::zero() == FrScalar::zero() );
    BOOST_CHECK( a * FrScalar::one() == a );
}

BOOST_AUTO_TEST_CASE( FrScalar_Negation ) {
    FrScalar a( 100 );
    FrScalar result = -a;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ),
        "21888242871839275222246405745257275088548364400416034343698204186575808495517" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Inverse ) {
    FrScalar a( 7 );
    FrScalar result = a.inverse();
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ),
        "3126891838834182174606629392179610726935480628630862049099743455225115499374" );
}

BOOST_AUTO_TEST_CASE( FrScalar_Pow_Basic ) {
    FrScalar three( 3 );
    auto p5 = power( three, 5 );
    BOOST_CHECK_EQUAL( p5.toString( Base::DEC ), "243" );
}

BOOST_AUTO_TEST_CASE( FrScalar_To_FromString ) {
    FrScalar fr = FrScalar::fromString( "12345", Base::DEC );
    BOOST_REQUIRE_EQUAL( fr.toString( Base::DEC ), "12345" );

    for ( size_t i = 0; i < 100; i++ ) {
        FrScalar r = FrScalar::random();
        auto s = r.toString( Base::HEXA );
        FrScalar r2 = FrScalar::fromString( s, Base::HEXA );
        BOOST_REQUIRE( r == r2 );

        s = r.toString( Base::DEC );
        r2 = FrScalar::fromString( s, Base::DEC );
        BOOST_REQUIRE( r == r2 );
    }
}

BOOST_AUTO_TEST_CASE( FrScalar_To_From_Bytes ) {
    for ( size_t i = 0; i < 100; ++i ) {
        FrScalar r = FrScalar::random();

        auto bytes = r.toByteArray();
        FrScalar r2 = FrScalar::fromBytes( bytes );
        BOOST_REQUIRE( r == r2 );

        auto bytesVec = r.toByteVector();
        FrScalar r3 = FrScalar::fromBytes( bytesVec );
        BOOST_REQUIRE( r == r3 );
    }
}


// ==================== FqElement Tests ====================

BOOST_AUTO_TEST_CASE( FqElement_Constructor_Default ) {
    FqElement fq;
    BOOST_REQUIRE( fq.isZero() );
    BOOST_REQUIRE_EQUAL( fq.toString( Base::DEC ), "0" );
}

BOOST_AUTO_TEST_CASE( FqElement_Constructor_Uint64 ) {
    FqElement fq( 123 );
    BOOST_REQUIRE_EQUAL( fq.toString( Base::DEC ), "123" );
}

BOOST_AUTO_TEST_CASE( FqElement_Zero ) {
    FqElement fq = FqElement::zero();
    BOOST_REQUIRE( fq.isZero() );
    BOOST_REQUIRE_EQUAL( fq.toString( Base::DEC ), "0" );
}

BOOST_AUTO_TEST_CASE( FqElement_One ) {
    FqElement fq = FqElement::one();
    BOOST_REQUIRE( fq.isOne() );
    BOOST_REQUIRE_EQUAL( fq.toString( Base::DEC ), "1" );
}

BOOST_AUTO_TEST_CASE( FqElement_Addition ) {
    FqElement a( 50 );
    FqElement b( 75 );
    FqElement result = a + b;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "125" );
}

BOOST_AUTO_TEST_CASE( FqElement_Subtraction ) {
    FqElement a( 100 );
    FqElement b( 30 );
    FqElement result = a - b;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "70" );
}

BOOST_AUTO_TEST_CASE( FqElement_Multiplication ) {
    FqElement a( 9 );
    FqElement b( 8 );
    FqElement result = a * b;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "72" );
}

BOOST_AUTO_TEST_CASE( FqElement_Power ) {
    FqElement a( 3 );
    FqElement result = a ^ 4;
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "81" );
}

BOOST_AUTO_TEST_CASE( FqElement_Pow_StringExponent ) {
    FqElement two( 2 );
    auto res = power( two, "10" );
    BOOST_CHECK_EQUAL( res.toString( Base::DEC ), "1024" );
}

BOOST_AUTO_TEST_CASE( FqElement_Add_Mul_Roundtrip_String ) {
    FqElement a( rnd64() ), b( rnd64() );
    FqElement s = a + b;
    FqElement p = a * b;
    // Round-trip via DEC strings must reconstruct exactly
    auto sa = a.toString( Base::DEC );
    auto sb = b.toString( Base::DEC );
    auto ss = s.toString( Base::DEC );
    auto sp = p.toString( Base::DEC );
    BOOST_CHECK( FqElement::fromString( sa, Base::DEC ) == a );
    BOOST_CHECK( FqElement::fromString( sb, Base::DEC ) == b );
    BOOST_CHECK( FqElement::fromString( ss, Base::DEC ) == s );
    BOOST_CHECK( FqElement::fromString( sp, Base::DEC ) == p );
}

BOOST_AUTO_TEST_CASE( FqElement_Sqrt ) {
    FqElement a( 4 );
    FqElement result = a.sqrt();
    BOOST_REQUIRE_EQUAL( result.toString( Base::DEC ), "2" );
}

BOOST_AUTO_TEST_CASE( FqElement_FromString ) {
    FqElement fq = FqElement::fromString( "987654321", Base::DEC );
    BOOST_REQUIRE_EQUAL( fq.toString( Base::DEC ), "987654321" );
}

BOOST_AUTO_TEST_CASE( FqElement_FromHash ) {
    std::array< uint8_t, 32 > hash = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    FqElement fq = hashToFq( hash );
    BOOST_REQUIRE_EQUAL( fq.toString( Base::DEC ),
        "455867356320691211509944977504407603390036387149619137164185182714736811808" );
}

BOOST_AUTO_TEST_CASE( FqElement_To_From_Bytes ) {
    for ( size_t i = 0; i < 100; ++i ) {
        FqElement r = FqElement::random();

        auto bytes = r.toByteArray();
        FqElement r2 = FqElement::fromBytes( bytes );
        BOOST_REQUIRE( r == r2 );
    }
}

BOOST_AUTO_TEST_CASE( FqElement_To_Ulong ) {
    FqElement fq( 123456789 );
    uint64_t ul = fq.toUlong();
    BOOST_REQUIRE_EQUAL( ul, ( uint64_t ) 123456789 );

    FqElement fq2 = FqElement::fromString(
        "4694625540791604852420020651969226497284382434318473048459679808020802528590", Base::DEC );
    uint64_t ul2 = fq2.toUlong();
    BOOST_REQUIRE_EQUAL( ul2, fq2.toUlong() );
    BOOST_REQUIRE_EQUAL( ul2, ( uint64_t ) 13508474536318821710ULL );  // actual sum from libff

    // points used on libff
    FqElement fq3 = FqElement::fromString(
        "3304936327297184941808578954020427106578801991031799403748685827818019345413", Base::DEC );
    FqElement fq4 = FqElement::fromString(
        "6649331365118568730715534986307847677699801977709336484131603449974370490941", Base::DEC );
    uint64_t sum = fq3.toUlong() + fq4.toUlong();

    BOOST_REQUIRE_EQUAL( sum, ( fq3 + fq4 ).toUlong() );
    BOOST_REQUIRE_EQUAL( sum, ( uint64_t ) 542074693502250562ULL );  // actual sum from libff
}

// ==================== Fq2Element Tests ====================

BOOST_AUTO_TEST_CASE( Fq2_Constructor ) {
    Fq2Element z;
    BOOST_REQUIRE( z.isZero() );
}

BOOST_AUTO_TEST_CASE( Fq2_One ) {
    Fq2Element z = Fq2Element::one();
    BOOST_REQUIRE( z.isOne() );
}

BOOST_AUTO_TEST_CASE( Fq2_Zero ) {
    Fq2Element z = Fq2Element::zero();
    BOOST_REQUIRE( z.isZero() );
}

// ==================== G1Point Tests ====================

BOOST_AUTO_TEST_CASE( G1_Constructor_Default ) {
    G1Point Z;  // default-constructed should be zero
    auto arr = Z.toStringArray( Base::DEC );
    BOOST_REQUIRE_EQUAL( arr.size(), ( size_t ) 2 );
    BOOST_CHECK_EQUAL( arr[0], "0" );
    BOOST_CHECK_EQUAL( arr[1], "1" );
}


BOOST_AUTO_TEST_CASE( G1Point_Constructor_Coordinates ) {
    FqElement x( 1 );
    FqElement y( 2 );
    G1Point g1( x, y );
    auto components = g1.toStringArray( Base::DEC );
    BOOST_REQUIRE_EQUAL( components[0], "1" );
    BOOST_REQUIRE_EQUAL( components[1], "2" );
}

BOOST_AUTO_TEST_CASE( G1Point_Addition ) {
    G1Point result = g1_1 + g1_2;
    auto components = result.toStringArray( Base::DEC );

    BOOST_REQUIRE_EQUAL( components[0],
        "14877282964938493996916829382196274212297042332082681544995330082760619382262" );
    BOOST_REQUIRE_EQUAL( components[1],
        "16289430191206282110840163143695136008335188480855279431126813382375446509749" );
}

BOOST_AUTO_TEST_CASE( G1Point_Subtraction ) {
    G1Point result = g1_1 - g1_2;
    auto components = result.toStringArray( Base::DEC );

    BOOST_REQUIRE_EQUAL( components[0],
        "11817726876598338124965856173127140282815337644155690676905442874390305740119" );
    BOOST_REQUIRE_EQUAL( components[1],
        "9925513893800878140024280556045826273055070534052571036975895240944486275401" );
}

BOOST_AUTO_TEST_CASE( G1Point_ScalarMultiplication ) {
    FrScalar scalar( 5 );
    G1Point result = scalar * g1_1;
    auto components = result.toStringArray( Base::DEC );

    BOOST_REQUIRE_EQUAL( components[0],
        "20376309673672285091036062995080236449560628223662404814029615442445251811807" );
    BOOST_REQUIRE_EQUAL( components[1],
        "18815753329130967154939045229228356477084942127534441953762664499284142156879" );
}

BOOST_AUTO_TEST_CASE( G1_Add_Neg_ScalarMul_Identities ) {
    G1Point P = g1_2;
    G1Point Z = G1Point::identity();
    FrScalar a( rnd64() ), b( rnd64() );

    BOOST_CHECK( P + Z == P );
    BOOST_CHECK( Z + P == P );
    BOOST_CHECK( P + ( -P ) == Z );
    BOOST_CHECK( a * ( P + P ) == a * P + a * P );
    BOOST_CHECK( ( a + b ) * P == a * P + b * P );
}

BOOST_AUTO_TEST_CASE( G1Point_GetX ) {
    G1Point g1( FqElement( 1 ), FqElement( 2 ) );
    FqElement x = g1.getX();
    BOOST_REQUIRE_EQUAL( x.toString( Base::DEC ), "1" );
}

BOOST_AUTO_TEST_CASE( G1Point_GetY ) {
    G1Point g1( FqElement( 1 ), FqElement( 2 ) );
    FqElement y = g1.getY();
    BOOST_REQUIRE_EQUAL( y.toString( Base::DEC ), "2" );
}

BOOST_AUTO_TEST_CASE( G1Point_FromHash_Array ) {
    std::array< uint8_t, 32 > hash = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140,
        150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 251, 252, 28, 29, 30, 31, 32 };
    G1Point g1 = G1Point::fromHash( hash );
    auto components = g1.toStringArray( Base::DEC );
    BOOST_REQUIRE_EQUAL( components[0],
        "4558673563206912115099449775044076033900363871496191371641849272994640043815" );
    BOOST_REQUIRE_EQUAL( components[1],
        "15979456021928985712867088770484417280199032966452305288208264796118968830390" );
}

BOOST_AUTO_TEST_CASE( G1Point_FromHash_String ) {
    G1Point g1 =
        G1Point::fromHash( "0A244F76B7D8C9980A244F76B7D8C9980A244F76B7D8C9980A244F76B7D8C998" );
    auto components = g1.toStringArray( Base::DEC );

    BOOST_REQUIRE_EQUAL( components[0],
        "4587283418761119468269290688587120945630972288154622897769030324647058000281" );
    BOOST_REQUIRE_EQUAL( components[1],
        "13192768488581010676554486357849517617288546777788875101446621238775087709044" );
}

BOOST_AUTO_TEST_CASE( G1Point_To_Bytes ) {
    std::array< uint8_t, G1Point::SIZE_BYTES > expected = { 39, 170, 13, 120, 78, 158, 214, 197,
        152, 142, 211, 227, 120, 43, 206, 169, 175, 189, 202, 134, 20, 179, 132, 128, 72, 23, 150,
        31, 153, 227, 3, 27, 28, 240, 233, 249, 194, 21, 173, 33, 38, 34, 199, 232, 54, 2, 46, 241,
        221, 36, 132, 53, 215, 243, 137, 239, 174, 202, 221, 112, 105, 163, 104, 137 };

    G1Point g1 = g1_2;
    auto bytes = g1.toByteArray();

    BOOST_REQUIRE( bytes == expected );
    G1Point g1_from_bytes = G1Point::fromBytes( bytes );
    BOOST_REQUIRE( g1 == g1_from_bytes );

    auto vec_bytes = g1.toByteVector();
    std::vector< uint8_t > expected_vec( expected.begin(), expected.end() );
    BOOST_REQUIRE( vec_bytes == expected_vec );
    G1Point g1_from_vec_bytes = G1Point::fromBytes( vec_bytes );
    BOOST_REQUIRE( g1 == g1_from_vec_bytes );

    // some more random points
    for ( int i = 0; i < 10; i++ ) {
        G1Point r = G1Point::random();
        auto b = r.toByteArray();
        G1Point r2 = G1Point::fromBytes( b );
        BOOST_REQUIRE( r == r2 );

        auto vb = r.toByteVector();
        G1Point r3 = G1Point::fromBytes( vb );
        BOOST_REQUIRE( r == r3 );
    }
}

BOOST_AUTO_TEST_CASE( G1Point_To_And_From_String ) {
    G1Point original = G1Point::random();

    // array & hexa
    auto str_arr = original.toStringArray( Base::HEXA );
    G1Point reconstructed = G1Point::fromString( str_arr, Base::HEXA );
    BOOST_REQUIRE( original == reconstructed );

    // array & decimal
    auto str_arr_dec = original.toStringArray( Base::DEC );
    G1Point reconstructed_dec = G1Point::fromString( str_arr_dec, Base::DEC );
    BOOST_REQUIRE( original == reconstructed_dec );

    // vector & hexa
    auto str_vec = original.toStringVector( Base::HEXA );
    G1Point reconstructed_vec = G1Point::fromString( str_vec, Base::HEXA );
    BOOST_REQUIRE( original == reconstructed_vec );

    // vector & decimal
    auto str_vec_dec = original.toStringVector( Base::DEC );
    G1Point reconstructed_vec_dec = G1Point::fromString( str_vec_dec, Base::DEC );
    BOOST_REQUIRE( original == reconstructed_vec_dec );

    // string & hexa
    auto str = original.toString( Base::HEXA );
    G1Point reconstructed_str = G1Point::fromString( str, Base::HEXA );
    BOOST_REQUIRE( original == reconstructed_str );

    // string & decimal
    // auto str_dec = original.toString(Base::DEC);
    // BOOST_REQUIRE_THROW(G1Point::fromString(str_dec, Base::DEC), ThresholdUtils::IncorrectInput
    // );
}

// ==================== G2Point Tests ====================

BOOST_AUTO_TEST_CASE( G2Point_Constructor_Default ) {
    G2Point g2;
    auto components = g2.toStringArray( Base::DEC );
    BOOST_REQUIRE_EQUAL( components.size(), ( size_t ) 4 );
    BOOST_REQUIRE_EQUAL( components[0], "0" );
    BOOST_REQUIRE_EQUAL( components[1], "0" );
    BOOST_REQUIRE_EQUAL( components[2], "1" );
    BOOST_REQUIRE_EQUAL( components[3], "0" );
}

BOOST_AUTO_TEST_CASE( G2Point_Addition ) {
    G2Point result = g2_1 + g2_2;
    auto components = result.toStringArray( Base::DEC );

    BOOST_REQUIRE_EQUAL( components[0],
        "14381522556927441357419395081401761967577535823515197181400413500799738019958" );
    BOOST_REQUIRE_EQUAL( components[1],
        "3671525381219463797034926322103871418512416431253153213870361976756904715850" );
    BOOST_REQUIRE_EQUAL( components[2],
        "12950197322016291023586989019441323894702362313811178219774877852256602279521" );
    BOOST_REQUIRE_EQUAL( components[3],
        "17959242138599084231597375613846776866059998991460966267024488668384078903177" );
}

BOOST_AUTO_TEST_CASE( G2Point_Subtraction ) {
    G2Point result = g2_1 - g2_2;
    auto components = result.toStringArray( Base::DEC );

    BOOST_REQUIRE_EQUAL( components[0],
        "11225298425980048770976794417700083169840939022009186004888573116294223924228" );
    BOOST_REQUIRE_EQUAL( components[1],
        "20991494887722664207694677662925003549506095456446913750846857410426451757883" );
    BOOST_REQUIRE_EQUAL( components[2],
        "19267830225150939541098637946281512414111253913119129411398848625344146875758" );
    BOOST_REQUIRE_EQUAL( components[3],
        "15640276905811039115656780695173612726234040458206846451749601192741330099616" );
}

BOOST_AUTO_TEST_CASE( G2Point_ScalarMultiplication ) {
    FrScalar scalar( 7 );
    G2Point result = scalar * g2_1;
    auto components = result.toStringArray( Base::DEC );

    BOOST_REQUIRE_EQUAL( components[0],
        "17548406117653466125662638252345930861615211905277953636350601323224576164163" );
    BOOST_REQUIRE_EQUAL( components[1],
        "1981743886841990602637819964891757712461395322781418310000637659805534927135" );
    BOOST_REQUIRE_EQUAL( components[2],
        "6570954395284518396460071405005598826773232571795753328947306210087478381510" );
    BOOST_REQUIRE_EQUAL( components[3],
        "16824501329755083452029385265017704609235028440289442434084340230585420944677" );
}

BOOST_AUTO_TEST_CASE( G2_Add_Neg_ScalarMul_Identities ) {
    G2Point P = g2_1;
    G2Point Z = G2Point::identity();
    FrScalar a( rnd64() ), b( rnd64() );

    BOOST_CHECK( P + Z == P );
    BOOST_CHECK( Z + P == P );
    BOOST_CHECK( P + ( -P ) == Z );
    BOOST_CHECK( a * ( P + P ) == a * P + a * P );
    BOOST_CHECK( ( a + b ) * P == a * P + b * P );
}

BOOST_AUTO_TEST_CASE( G2Point_To_And_From_Bytes ) {
    G2Point original = G2Point::random();
    auto bytes = original.toByteArray();
    G2Point reconstructed = G2Point::fromBytes( bytes );
    BOOST_REQUIRE( original == reconstructed );

    auto vec_bytes = original.toByteVector();
    G2Point reconstructed_vec = G2Point::fromBytes( vec_bytes );
    BOOST_REQUIRE( original == reconstructed_vec );
}

BOOST_AUTO_TEST_CASE( G2Point_To_And_From_String ) {
    G2Point original = G2Point::random();

    // array & hexa
    auto str_arr = original.toStringArray( Base::HEXA );
    G2Point reconstructed = G2Point::fromString( str_arr, Base::HEXA );
    BOOST_REQUIRE( original == reconstructed );

    // array & decimal
    auto str_arr_dec = original.toStringArray( Base::DEC );
    G2Point reconstructed_dec = G2Point::fromString( str_arr_dec, Base::DEC );
    BOOST_REQUIRE( original == reconstructed_dec );

    // vector & hexa
    auto str_vec = original.toStringVector( Base::HEXA );
    G2Point reconstructed_vec = G2Point::fromString( str_vec, Base::HEXA );
    BOOST_REQUIRE( original == reconstructed_vec );

    // vector & decimal
    auto str_vec_dec = original.toStringVector( Base::DEC );
    G2Point reconstructed_vec_dec = G2Point::fromString( str_vec_dec, Base::DEC );
    BOOST_REQUIRE( original == reconstructed_vec_dec );

    // string & hexa
    auto str = original.toString( Base::HEXA );
    G2Point reconstructed_str = G2Point::fromString( str, Base::HEXA );
    BOOST_REQUIRE( original == reconstructed_str );

    // string & decimal
    // auto str_dec = original.toString(Base::DEC);
    // BOOST_REQUIRE_THROW(G2Point::fromString(str_dec, Base::DEC), ThresholdUtils::IncorrectInput
    // );
}

BOOST_AUTO_TEST_SUITE_END()
