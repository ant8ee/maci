use super::poseidon::{PoseidonT3, PoseidonT6};
use ink_prelude::vec::Vec;
pub struct Hasher;
impl Hasher {
    pub fn hash5(array: [[u8; 32]; 5]) -> [u8; 32] {
        PoseidonT6::poseidon(array)
    }
    pub fn hash11(array: Vec<[u8; 32]>) -> [u8; 32] {
        let mut input11 = [[0u8; 32]; 11];
        let mut first5 = [[0u8; 32]; 5];
        let mut second5 = [[0u8; 32]; 5];
        for i in 0..array.len() {
            input11[i] = array[i];
        }
        for i in 0..5 {
            first5[i] = input11[i];
            second5[i] = input11[i + 5];
        }

        let first2 = [PoseidonT6::poseidon(first5), PoseidonT6::poseidon(second5)];
        let second2 = [PoseidonT3::poseidon(first2), input11[10]];
        PoseidonT3::poseidon(second2)
    }
    pub fn hash_left_right(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        PoseidonT3::poseidon([left, right])
    }
}
