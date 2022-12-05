 use ink_prelude::{
        string::{
            String,
           
        },
        vec::Vec,
    };

use substrate_bn::{
    arith::U256, pairing_batch, Fq, Fq2, Fr, Group, Gt, G1 as G1Point, G2 as G2Point,
};
pub struct VerifyingKey {
    pub alpha1: G1Point,
    pub beta2: G2Point,
    pub gamma2: G2Point,
    pub delta2: G2Point,
    pub ic: Vec<G1Point>,
}

pub struct Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

pub struct Pairing;
impl Pairing {
    pub const SNARK_SCALAR_FIELD: &'static str =
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    pub const PRIME_Q: &'static str =
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    pub fn snark_scalar_field() -> U256 {
        Fr::from_str(&Self::SNARK_SCALAR_FIELD).unwrap().into_u256()
    }
    pub fn prime_q() -> U256 {
        Fq::from_str(&Self::PRIME_Q).unwrap().into_u256()
    }
    
    pub fn vec_to_g1point(vec: &Vec<String>) -> G1Point {
        G1Point::new(
            Fq::from_str(&vec[0]).unwrap(),
            Fq::from_str(&vec[1]).unwrap(),
            Fq::one(),
        )
    }
    pub fn vec_to_g2point(vec: &Vec<Vec<String>>) -> G2Point {
        G2Point::new(
            Fq2::new(
                Fq::from_str(&vec[0][0]).unwrap(),
                Fq::from_str(&vec[0][1]).unwrap(),
            ),
            Fq2::new(
                Fq::from_str(&vec[1][0]).unwrap(),
                Fq::from_str(&vec[1][1]).unwrap(),
            ),
            Fq2::one(),
        )
    }
    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero.
     */
    pub fn negate(p: G1Point) -> G1Point {
        // The prime q in the base field F_q for G1
        if p.is_zero() {
            p
        } else {
            -p
        }
    }

    /*
     * @return The sum of two points of G1
     */
    pub fn plus(p1: G1Point, p2: G1Point) -> G1Point {
        p1 + p2
    }

    /*
     * @return The product of a point on G1 and a scalar, i.e.
     *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     *         points p.
     */
    pub fn scalar_mul(p: G1Point, s: Fr) -> G1Point {
        p * s
    }

    /* @return The result of computing the pairing check
     *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
     *         For example,
     *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
     */
    pub fn pairing(pairs: &[(G1Point, G2Point)]) -> bool {
        pairing_batch(pairs) == Gt::one()
    }
}
