use crate::tree::hasher::Poseidon;
use dusk_bls12_381::BlsScalar;
use ink_prelude::vec::Vec;
pub struct PoseidonT3;
impl PoseidonT3 {
    pub fn poseidon(input: [[u8; 32]; 2]) -> [u8; 32] {
        let b = input
            .into_iter()
            .map(|x| Poseidon::bytes_to_scalar(x))
            .collect::<Vec<BlsScalar>>();
        let result = dusk_poseidon::sponge::hash(&b);
        Poseidon::scalar_to_bytes(result)
    }
}

pub struct PoseidonT6;
impl PoseidonT6 {
    pub fn poseidon(input: [[u8; 32]; 5]) -> [u8; 32] {
        let b = input
            .into_iter()
            .map(|x| Poseidon::bytes_to_scalar(x))
            .collect::<Vec<BlsScalar>>();
        let result = dusk_poseidon::sponge::hash(&b);
        Poseidon::scalar_to_bytes(result)
    }
}
