/*
    Copyright (C) 2018-2019 SKALE Labs

    This file is part of libBLS.

    libBLS is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libBLS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with libBLS. If not, see <https://www.gnu.org/licenses/>.

    @file unit_tests_te.cpp
    @author Oleh Nikolaiev
    @date 2019
 */


#include <bls/bls.h>

#include <cstdlib>
#include <ctime>
#include <map>
#include <set>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>


#define BOOST_TEST_MODULE

#include <boost/test/included/unit_test.hpp>

class G2 {
 public:
    G2();
    G2(const libff::alt_bn128_Fq12& X, const libff::alt_bn128_Fq12& Y, const libff::alt_bn128_Fq12& Z) : X(X), Y(Y), Z(Z) {};

    static G2 G2_zero;

    libff::alt_bn128_Fq12 X, Y, Z;

    G2 operator+(const G2& other) const;

    G2 dbl() const;

    void to_affine_coordinates();

    static G2 zero() { return G2_zero; };

    bool is_zero() const { return this->Z.is_zero(); };

    bool operator==(const G2& other) const;
    bool operator!=(const G2& other) const;
};

void G2::to_affine_coordinates() {
    if (this->is_zero()) {
      this->X = libff::alt_bn128_Fq12::zero();
      this->Y = libff::alt_bn128_Fq12::one();
      this->Z = libff::alt_bn128_Fq12::zero();
    }
    else {
      libff::alt_bn128_Fq12 Z_inv = Z.inverse();
      libff::alt_bn128_Fq12 Z2_inv = Z_inv.squared();
      libff::alt_bn128_Fq12 Z3_inv = Z2_inv * Z_inv;
      this->X = this->X * Z2_inv;
      this->Y = this->Y * Z3_inv;
      this->Z = libff::alt_bn128_Fq12::one();
    }
}

G2 G2::dbl() const {
    if (this->is_zero()) {
      return (*this);
    }

    libff::alt_bn128_Fq12 A = (this->X).squared();
    libff::alt_bn128_Fq12 B = (this->Y).squared();
    libff::alt_bn128_Fq12 C = B.squared();
    libff::alt_bn128_Fq12 D = (this->X + B).squared() - A - C;
    D = D+D;
    libff::alt_bn128_Fq12 E = A + A + A;
    libff::alt_bn128_Fq12 F = E.squared();
    libff::alt_bn128_Fq12 X3 = F - (D+D);
    libff::alt_bn128_Fq12 eightC = C+C;
    eightC = eightC + eightC;
    eightC = eightC + eightC;
    libff::alt_bn128_Fq12 Y3 = E * (D - X3) - eightC;
    libff::alt_bn128_Fq12 Y1Z1 = (this->Y) * (this->Z);
    libff::alt_bn128_Fq12 Z3 = Y1Z1 + Y1Z1;

    return G2(X3, Y3, Z3);
}

G2 G2::operator+(const G2& other) const {
  
  if (this->is_zero()) {
      return other;
    }

    if (other.is_zero()) {
      return *this;
    }

    libff::alt_bn128_Fq12 Z1Z1 = (this->Z).squared();
    libff::alt_bn128_Fq12 Z2Z2 = (other.Z).squared();

    libff::alt_bn128_Fq12 U1 = this->X * Z2Z2;
    libff::alt_bn128_Fq12 U2 = other.X * Z1Z1;

    libff::alt_bn128_Fq12 Z1_cubed = (this->Z) * Z1Z1;
    libff::alt_bn128_Fq12 Z2_cubed = (other.Z) * Z2Z2;

    libff::alt_bn128_Fq12 S1 = (this->Y) * Z2_cubed;
    libff::alt_bn128_Fq12 S2 = (other.Y) * Z1_cubed;

    if (U1 == U2 && S1 == S2) {
        return this->dbl();
    }

    libff::alt_bn128_Fq12 H = U2 - U1;
    libff::alt_bn128_Fq12 S2_minus_S1 = S2-S1;
    libff::alt_bn128_Fq12 I = (H+H).squared();
    libff::alt_bn128_Fq12 J = H * I;
    libff::alt_bn128_Fq12 r = S2_minus_S1 + S2_minus_S1;
    libff::alt_bn128_Fq12 V = U1 * I;
    libff::alt_bn128_Fq12 X3 = r.squared() - J - (V+V);
    libff::alt_bn128_Fq12 S1_J = S1 * J;
    libff::alt_bn128_Fq12 Y3 = r * (V-X3) - (S1_J+S1_J);
    libff::alt_bn128_Fq12 Z3 = ((this->Z+other.Z).squared()-Z1Z1-Z2Z2) * H;

    return G2(X3, Y3, Z3);
}

bool G2::operator==(const G2& other) const {
    if (this->is_zero()) {
      return other.is_zero();
    }

    if (other.is_zero()) {
      return false;
    }

    libff::alt_bn128_Fq12 Z1_squared = (this->Z).squared();
    libff::alt_bn128_Fq12 Z2_squared = (other.Z).squared();

    if ((this->X * Z2_squared) != (other.X * Z1_squared)) {
      return false;
    }

    libff::alt_bn128_Fq12 Z1_cubed = (this->Z) * Z1_squared;
    libff::alt_bn128_Fq12 Z2_cubed = (other.Z) * Z2_squared;

    if ((this->Y * Z2_cubed) != (other.Y * Z1_cubed)) {
      return false;
    }

    return true;
}

bool G2::operator!=(const G2& other) const {
  return !(operator==(other));
}

G2 G2::G2_zero = G2(libff::alt_bn128_Fq12::zero(),
                  libff::alt_bn128_Fq12::one(),
                  libff::alt_bn128_Fq12::zero());;


G2 FrobeniusMap(const G2& other, size_t pow) {
  G2 copy = other;
  copy.to_affine_coordinates();

  libff::alt_bn128_Fq12 x = copy.X.Frobenius_map(pow);
  libff::alt_bn128_Fq12 y = copy.Y.Frobenius_map(pow);
  libff::alt_bn128_Fq12 z = copy.Z.Frobenius_map(pow);

  G2 ret = G2(x, y, z);

  return ret;
}

libff::alt_bn128_G1 FrobeniusTrace(const G2& other) {
  G2 temp  = G2::zero();
  temp.to_affine_coordinates();

  for (size_t i = 0; i < 12; ++i) {
    temp = temp + FrobeniusMap(other, i);
    temp.to_affine_coordinates();
  }

  temp.to_affine_coordinates();

  libff::alt_bn128_G1 ret = libff::alt_bn128_G1(temp.X.c0.c0.c0, temp.Y.c0.c0.c0, temp.Z.c0.c0.c0);

  ret.print_coordinates();

  std::cout << "G1 " << ret.is_well_formed() << '\n';

  return ret;
}

libff::alt_bn128_G1 G2ToG1(const libff::alt_bn128_G2& other, const libff::alt_bn128_Fq12& z) {
  libff::alt_bn128_G2 copy = other;
  copy.to_affine_coordinates();
  G2 point = G2(other.X * (z * z), other.Y * (z * z * z), other.Z * libff::alt_bn128_Fq12::one());
  libff::alt_bn128_G1 result = libff::alt_bn128_Fr("12").inverse() * FrobeniusTrace(point);

  return result;
}

BOOST_AUTO_TEST_SUITE(ThresholdEncryption)

BOOST_AUTO_TEST_CASE(TE) {
  libff::init_alt_bn128_params();

  libff::alt_bn128_Fq12 psi = libff::alt_bn128_Fq12(libff::alt_bn128_Fq6(libff::alt_bn128_Fq2(libff::alt_bn128_Fq(9), libff::alt_bn128_Fq(1)), libff::alt_bn128_Fq2::zero(), libff::alt_bn128_Fq2::zero()), libff::alt_bn128_Fq6::zero());

  libff::bigint<12 * libff::alt_bn128_q_limbs> expo = libff::bigint<12 * libff::alt_bn128_q_limbs>("335914141338562145149817583821088190989531600367196620213390157824306204175579960837211643303929267575682517621615232755167225261764071035501705673597610447327882531665388904999866663967462062888675849288672744216562953430000735554934986230196232200251009205270844330131329605716488167948741287442627885177104712385023654435311116364078321581820388633172154401338032077791550910836324254900633240979347215189327656262508307633170668014616615184442056149716798756709120325224401561118349917046297176128123504518235328009720609473228958355589046635600564794202002434305981057716513158489685321464274936503895125174157546453541715191726542013395026243848788173332093849380329481009910810565920152408503962248106054686728724444996914494920606607112587675662520843479306888294105025346844321872360220357349684451936011012677106428027767333768468286975425535970490403374107950772714685654933847241218904501507753742359560");
  libff::bigint<12 * libff::alt_bn128_q_limbs> smth = libff::bigint<12 * libff::alt_bn128_q_limbs>("2015484848031372870898905502926529145937189602203179721280340946945837225053479765023269859823575605454095105729691396531003351570584426213010234041585662683967295189992333429999199983804772377332055095732036465299377720580004413329609917381177393201506055231625065980787977634298929007692447724655767311062628274310141926611866698184469929490922331799032926408028192466749305465017945529403799445876083291135965937575049845799024008087699691106652336898300792540254721951346409366710099502277783056768741027109411968058323656839373750133534279813603388765212014605835886346299078950938111928785649619023370751044945278721250291150359252080370157463092729039992563096281976886059464863395520914451023773488636328120372346669981486969523639642675526053975125060875841329764630152081065931234161322144098106711616066076062638568166604002610809721852553215822942420244647704636288113929603083447313427009046522454157360");

  libff::alt_bn128_Fq12 z = libff::power(psi, expo);
  libff::alt_bn128_Fq12 z2 = z * z;
  libff::alt_bn128_Fq12 z3 = z * z2;
  libff::alt_bn128_Fq12 z6 = z3 * z3;

  BOOST_REQUIRE(libff::power(psi, smth) == libff::alt_bn128_Fq12::one());
  BOOST_REQUIRE(z6 == psi);

  libff::alt_bn128_G2 some = libff::alt_bn128_Fr("17") * libff::alt_bn128_G2::one();

  some.to_affine_coordinates();

  auto res = G2ToG1(some, z);

  res.print_coordinates();

  BOOST_REQUIRE(res == libff::alt_bn128_Fr("17") * libff::alt_bn128_G1::one());
}

BOOST_AUTO_TEST_SUITE_END()
