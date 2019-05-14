#include <threshold_encryption/utils.h>

class G2 {
 public:
    libff::alt_bn128_Fq12 X, Y;

    G2();

    G2(const libff::alt_bn128_Fq12& x, const libff::alt_bn128_Fq12& y) : X(x), Y(y) {};

    G2(const libff::alt_bn128_Fq2& x, const libff::alt_bn128_Fq2& y) {
      libff::alt_bn128_Fq12 z = libff::alt_bn128_Fq12(libff::alt_bn128_Fq6::zero(), libff::alt_bn128_Fq6::one());
      libff::alt_bn128_Fq12 z2 = z.squared();
      libff::alt_bn128_Fq12 z3 = z * z2;
      
      libff::alt_bn128_Fq12 g2_x = x * z2;
      libff::alt_bn128_Fq12 g2_y = y * z3;

      this->X = g2_x;
      this->Y = g2_y;
    }

    G2(const libff::alt_bn128_G2& elem) {
      libff::alt_bn128_G2 copy = elem;
      copy.to_affine_coordinates();

      G2 temp = G2(copy.X, copy.Y);
      this->X = temp.X;
      this->Y = temp.Y;
    }

    bool IsWellFormed() {
      libff::alt_bn128_Fq12 x3 = this->X.squared() * this->X;
      libff::alt_bn128_Fq12 y2 = this->Y.squared();

      return (y2 == x3 + libff::alt_bn128_Fq(3) * libff::alt_bn128_Fq12::one());
    }

    bool operator==(const G2& other) const {
      return (this->X == other.X && this->Y == other.Y);
    }

    bool operator!=(const G2& other) const {
      return !(operator==(other));
    }

    G2 operator+(const G2& other) const {
      if (this->X == other.X) {
        if (this->Y == other.Y) {
          return this->dbl();
        } else {
          return G2(libff::alt_bn128_Fq12::zero(), libff::alt_bn128_Fq12::zero());
        }
      }

      libff::alt_bn128_Fq12 lambda = (this->Y - other.Y) * (this->X - other.X).inverse();

      libff::alt_bn128_Fq12 x = lambda.squared() - this->X - other.X;
      libff::alt_bn128_Fq12 y = lambda * (this->X - x) - this->Y;

      return G2(x, y);
    }

    G2 dbl() const {
      libff::alt_bn128_Fq12 lambda = libff::alt_bn128_Fq(3) * this->X.squared() * (libff::alt_bn128_Fq(2) * this->Y).inverse();

      libff::alt_bn128_Fq12 x = lambda.squared() - this->X - this->X;
      libff::alt_bn128_Fq12 y = -(lambda * lambda.squared()) + lambda * this->X + lambda * this->X + lambda * this->X - this->Y;

      return G2(x, y);
    }
};

libff::alt_bn128_Fq CurveEquation(const libff::alt_bn128_Fq& field_elem) {
  return ((field_elem ^ 3) + libff::alt_bn128_Fq(3)); 
}

bool IsQuadraticResidue(const libff::alt_bn128_Fq& field_elem) {
  return (field_elem ^ field_elem.euler) == libff::alt_bn128_Fq::one();
}

libff::alt_bn128_Fq SquareRoot(const libff::alt_bn128_Fq& field_elem) {
  if (!IsQuadraticResidue(field_elem)) {
    throw std::runtime_error("Given element is a quadratic nonresiue");
  }

  return field_elem.sqrt();
}

libff::alt_bn128_Fq12 ComputeLine(const G2& R, const G2& P, const G2& Q) {
  libff::alt_bn128_Fq12 D = (P.X - R.X).inverse();

  libff::alt_bn128_Fq12 A = (P.Y - R.Y) * D;

  libff::alt_bn128_Fq12 B = (P.X * R.Y - R.X * P.Y) * D;

  libff::alt_bn128_Fq12 res = Q.Y - A * Q.X - B;

  return res; 
}

libff::alt_bn128_Fq12 ComputeTangentLine(const G2& P, const G2& Q) {
  libff::alt_bn128_Fq12 z = libff::alt_bn128_Fq12(libff::alt_bn128_Fq6::zero(), libff::alt_bn128_Fq6::one());

  libff::alt_bn128_Fq12 X2 = P.X.squared();
  libff::alt_bn128_Fq12 X2_3 = libff::alt_bn128_Fq(3) * X2;
  libff::alt_bn128_Fq12 Ydbl = libff::alt_bn128_Fq(2) * P.Y;
  libff::alt_bn128_Fq12 Ydbl_inv = Ydbl.inverse();
  libff::alt_bn128_Fq12 A = X2_3 * Ydbl_inv;
  libff::alt_bn128_Fq12 Y2 = P.Y.squared();
  libff::alt_bn128_Fq12 U = -Y2 + libff::alt_bn128_Fq(9) * libff::alt_bn128_Fq12::one();
  libff::alt_bn128_Fq12 B = U * Ydbl_inv;

  libff::alt_bn128_Fq12 res = Q.Y - A * Q.X - B;

  return res; 
}

libff::alt_bn128_Fq12 ComputeVerticalLine(const G2& P, const G2& Q) {
  return (Q.X - P.X);
}

libff::alt_bn128_Fq12 MillerLoop(const G2& P, const G2& Q) {
  libff::alt_bn128_Fq12 f = libff::alt_bn128_Fq12::one();

  G2 R = P;

  const G2 Qdbl = Q.dbl();

  for (long int i = libff::alt_bn128_modulus_r.num_bits() - 2; i >= 0; --i) {
    const bool bit = libff::alt_bn128_modulus_r.test_bit(i);

    libff::alt_bn128_Fq12 tangent_line_dbl = ComputeTangentLine(R, Qdbl);
    libff::alt_bn128_Fq12 tangent_line = ComputeTangentLine(R, Q);

    R = R.dbl();

    f = f.squared();
    f = f * tangent_line_dbl * ComputeVerticalLine(R, Q) * tangent_line.inverse() * ComputeVerticalLine(R, Qdbl).inverse();
    if (bit) {
      libff::alt_bn128_Fq12 line = ComputeLine(R, P, Q);
      libff::alt_bn128_Fq12 line_dbl = ComputeLine(R, P, Qdbl);

      R = R + P;

      f = f * line_dbl * ComputeVerticalLine(R, Q) * line.inverse() * ComputeVerticalLine(R, Qdbl).inverse();
    }
  }

  return f;
}

libff::alt_bn128_GT WeilPairing(const libff::alt_bn128_G2& Pc, const libff::alt_bn128_G2& Qc) {
  G2 P = G2(Pc);
  G2 Q = G2(Qc);

  libff::alt_bn128_Fq12 f = MillerLoop(P, Q);
  libff::alt_bn128_Fq12 g = MillerLoop(Q, P);

  libff::alt_bn128_Fq12 miller = f * g.inverse();
  miller.print();

  return miller;
}
