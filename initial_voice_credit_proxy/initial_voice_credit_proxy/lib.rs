#![cfg_attr(not(feature = "std"), no_std)]

//! Traits are extracted into a separate crate to show how the user can import
//! several foreign traits and implement those for the contract.

use ink_lang as ink;
use ink_prelude::vec::Vec;
use ink_env::AccountId;
type Balance = <ink_env::DefaultEnvironment as ink_env::Environment>::Balance;

#[ink::trait_definition]
pub trait InitialVoiceCreditProxy{
 
    #[ink(message)]
    fn get_voice_credits(&self,
        user:AccountId,
        data:Vec<u8>,
    )->Balance ;
}
