use super::hasher::Hasher;
use crate::maci::{Message, StateLeaf};
use crate::tree::hasher::Poseidon;
use dusk_bls12_381::BlsScalar;
use ink_prelude::{vec, vec::Vec};
pub struct DomainObjs;
impl DomainObjs {
    pub fn hash_state_leaf(state_leaf: &StateLeaf) -> [u8; 32] {
        let plaintext = [
            state_leaf.pub_key.x,
            state_leaf.pub_key.y,
            state_leaf.vote_option_tree_root,
            state_leaf.voice_credit_balance,
            state_leaf.nonce,
        ];
        Hasher::hash5(plaintext)
    }
    pub fn hash_message(message: &Message) -> [u8; 32] {
        let mut plaintext = vec![[0u8; 32]; 11];
        plaintext[0] = message.iv;
        plaintext[1..].copy_from_slice(&message.data);
        Hasher::hash11(plaintext)
    }
}
