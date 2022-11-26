#![cfg_attr(not(feature = "std"), no_std)]
pub use self::free_for_all_signup_gatekeeper::{
    FreeForAllSignupGatekeeper, FreeForAllSignupGatekeeperRef,
};

use ink_lang as ink;

#[ink::contract]
mod free_for_all_signup_gatekeeper {
    use super::*;
    use ink_prelude::vec::Vec;
    use signup_gatekeeper::SignUpGatekeeper;
    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    #[derive(ink_storage::traits::SpreadAllocate)]
    pub struct FreeForAllSignupGatekeeper {}

    impl FreeForAllSignupGatekeeper {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new() -> Self {
            ink::utils::initialize_contract(|_: &mut Self| {})
        }
    }
    impl SignUpGatekeeper for FreeForAllSignupGatekeeper {
        #[ink(message)]
        fn register(&mut self, _user: AccountId, _data: Vec<u8>) {}
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

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {}
    }
}
