#![cfg_attr(not(feature = "std"), no_std)]
pub use self::constant_initial_voice_credit_proxy::{
    ConstantInitialVoiceCreditProxy, ConstantInitialVoiceCreditProxyRef,
};

use ink_lang as ink;

#[ink::contract]
mod constant_initial_voice_credit_proxy {
    use initial_voice_credit_proxy::InitialVoiceCreditProxy;
    use ink_prelude::vec::Vec;
    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct ConstantInitialVoiceCreditProxy {
        balance: Balance,
    }

    impl ConstantInitialVoiceCreditProxy {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(balance: Balance) -> Self {
            Self { balance }
        }
    }
    impl InitialVoiceCreditProxy for ConstantInitialVoiceCreditProxy {
        #[ink(message)]
        fn get_voice_credits(&self, _user: AccountId, _data: Vec<u8>) -> Balance {
            self.balance
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

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {}

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {}
    }
}
