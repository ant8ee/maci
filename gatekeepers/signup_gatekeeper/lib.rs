#![cfg_attr(not(feature = "std"), no_std)]

//! Traits are extracted into a separate crate to show how the user can import
//! several foreign traits and implement those for the contract.

use ink_lang as ink;
use ink_prelude::vec::Vec;
use ink_env::AccountId;
use ink_env::Error;
#[ink::trait_definition]
pub trait SignUpGatekeeper {
 
    #[ink(message)]
    fn register(&mut self,
        user:AccountId,
        data:Vec<u8>,
    );
}
