#![cfg_attr(not(feature = "std"), no_std)]
pub use self::quin_merkle_tree::{QuinMerkleTree, QuinMerkleTreeRef};
mod hasher;
use ink_lang as ink;
macro_rules! ensure {
    ( $condition:expr, $error:expr $(,)? ) => {{
        if !$condition {
            return ::core::result::Result::Err(::core::convert::Into::into($error));
        }
    }};
}
#[ink::contract]
mod quin_merkle_tree {
    use super::*;

    use ink_prelude::{string::String, vec::Vec};
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use crate::hasher::{Poseidon,MerkleTreeHasher};

    /// Merkle tree maximum depth
    pub const MAX_DEPTH: u8 = 32;

    /// The number of leaves per node
    pub const LEAVES_PER_NODE: usize = 5;

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct QuinMerkleTree {
        ///Current root index in the history
        pub root: [u8; 32],
        pub tree_levels: u8,
        /// Next leaf index
        pub next_leaf_index: u64,
        ///Hashes last filled subtrees on every level
        pub filled_subtrees: Mapping<(u8, u8), [u8; 32]>,
        /// Merkle tree roots history
        pub roots: Mapping<[u8; 32], bool>,
    }
    /// Errors which my be returned from the smart contract
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        ///Merkle tree is full
        MerkleTreeIsFull,
        ///Depth should be in range 1..MAX_DEPTH
        DepthTooLong,
        ///Depth can not be 0
        DepthIsZero,
    }
    pub type Result<T> = core::result::Result<T, Error>;

    impl QuinMerkleTree {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(tree_levels: u8) -> Self {

            assert!(tree_levels <= MAX_DEPTH, "DepthTooLong");
            assert!(tree_levels>0 , "DepthIsZero");
            // let mut current_zero = zero_value;
            // let mut zeros = Array([zero_value; self.tree_levels]);
            // for i in 0..self.tree_levels {
            //     let temp = [current_zero; LEAVES_PER_NODE];
            //     zeros.0[i] = current_zero;
            //     current_zero = Poseidon::hash5(temp);
            // }

            // for i in 0..self.tree_levels {
            //     filled_subtrees.0[i] = [zeros.0[i]; LEAVES_PER_NODE];
            // }
            ink::utils::initialize_contract(|se1f: &mut Self| {
                se1f.tree_levels=tree_levels;
                se1f.root= Poseidon::ZEROS[tree_levels as usize-1];
             })
        }

        /*
         * @returns Whether the proof is valid given the hardcoded verifying key
         *          above and the public inputs
         */
        #[ink(message)]
        /// Get last root hash
        pub fn get_last_root(&self) -> [u8; 32] {
            self.root
        }

        /// Check existing provided root in roots history
        #[ink(message)]
        pub fn is_known_root(&self, root: [u8; 32]) -> bool {
            self.roots.get(&root).unwrap_or(false)
        }

        ///Insert leaf in the merkle tree
        #[ink(message)]
        pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u64> {
            let next_index = self.next_leaf_index as usize;

            if self.next_leaf_index == (2 as u64).pow(self.tree_levels as u32) {
                return Err(Error::MerkleTreeIsFull);
            }

            let mut current_index = next_index;
            let mut current_hash = leaf;

            // The leaf's relative position within its node
            let mut m = current_index % LEAVES_PER_NODE;
            let mut temp=[[0u8;32];LEAVES_PER_NODE];
            for i in 0..self.tree_levels {
                // If the leaf is at relative index 0, zero out the level in
                // filledSubtrees
                if m == 0 {
                    for j in 1..LEAVES_PER_NODE{
                    self.filled_subtrees.insert(&(i,j as u8),&Poseidon::ZEROS[i as usize]);
                    }
                   
                }
                self.filled_subtrees.insert(&(i,m as u8),&current_hash);
                for j in 0..LEAVES_PER_NODE {
                    temp[j]=self.filled_subtrees.get(&(i,j as u8)).unwrap_or(Poseidon::ZEROS[i as usize]);
                }
                current_hash = Poseidon::hash5(temp);
                current_index /= LEAVES_PER_NODE;
                m = current_index % LEAVES_PER_NODE;
            }

            self.roots.insert(current_hash, &true);

            self.next_leaf_index += 1;

            Ok(next_index as u64)
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;
        #[test]
            fn test_check_zeros_correctness_poseidon() {
                let mut result: [u8; 32] = Default::default();
                use ink_env::hash::CryptoHash;
                ink_env::hash::Blake2x256::hash(b"slushie", &mut result);
                let result = Poseidon::bytes_to_u64(result);

                let mut result = dusk_bls12_381::BlsScalar::from_raw(result);

                for i in 0..MAX_DEPTH as usize {
                    let b= Poseidon::scalar_to_bytes(result);
                    let s=b.iter().fold(String::new(),|mut a,x|{a.push_str(format!("{:02X}",x).as_str());a});
                    ink_env::debug_println!("hex!({:?}),",s);
                    // assert_eq!(b, Poseidon::ZEROS[i]);
                    result = dusk_poseidon::sponge::hash(&[result, result]);
                }
            }
            #[test]
            fn test_check_zeros5_correctness_poseidon() {
                let mut result: [u8; 32] = Default::default();
                use ink_env::hash::CryptoHash;
                ink_env::hash::Blake2x256::hash(b"slushie", &mut result);
                let result = Poseidon::bytes_to_u64(result);

                let mut result = dusk_bls12_381::BlsScalar::from_raw(result);

                for i in 0..MAX_DEPTH as usize {
                    let b= Poseidon::scalar_to_bytes(result);
                    let s=b.iter().fold(String::new(),|mut a,x|{a.push_str(format!("{:02X}",x).as_str());a});
                    ink_env::debug_println!("hex!({:?}),",s);
                    assert_eq!(b, Poseidon::ZEROS[i]);
                    result = dusk_poseidon::sponge::hash(&[result; LEAVES_PER_NODE]);
                }
            }
    }
}
