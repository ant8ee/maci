#![cfg_attr(not(feature = "std"), no_std)]
pub use self::signup_token_gatekeeper::{SignUpTokenGatekeeper, SignUpTokenGatekeeperRef};

use ink_lang as ink;

#[ink::contract]
mod signup_token_gatekeeper {
    use super::*;

    use ink_prelude::vec::Vec;
    use ink_storage::Mapping;
    use signup_gatekeeper::SignUpGatekeeper;
    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    #[derive(ink_storage::traits::SpreadAllocate)]
    pub struct SignUpTokenGatekeeper {
        token: AccountId,
        registered_token_ids: Mapping<u128, bool>,
    }
    /// Errors which my be returned from the smart contract
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        TransactionFailed,
    }

    pub type Result<T> = core::result::Result<T, Error>;
    impl SignUpTokenGatekeeper {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(token: AccountId) -> Self {
            ink::utils::initialize_contract(|se1f: &mut Self| {
                se1f.token = token;
            })
        }
        #[cfg_attr(test, allow(unused_variables))]
        fn erc721_owner_of(&self, token: AccountId, token_id: u32) -> Result<Option<AccountId>> {
            #[cfg(test)]
            {
                Ok(self.test_token_owner.get(&token_id))
            }
            #[cfg(not(test))]
            {
                use ink_env::call::{build_call, Call, ExecutionInput};
                let selector: [u8; 4] = [0x48, 0x39, 0x17, 0x41]; //Erc721::owner_of
                let (gas_limit, transferred_value) = (0, 0);
                build_call::<<Self as ::ink_lang::reflect::ContractEnv>::Env>()
                    .call_type(
                        Call::new()
                            .callee(token)
                            .gas_limit(gas_limit)
                            .transferred_value(transferred_value),
                    )
                    .exec_input(ExecutionInput::new(selector.into()).push_arg(token_id))
                    .returns::<Option<AccountId>>()
                    .fire()
                    .map_err(|e| {
                        ink_env::debug_println!("erc721_owner_of= {:?}", e);
                        Error::TransactionFailed
                    })
            }
        }
    }
    impl SignUpGatekeeper for SignUpTokenGatekeeper {
        #[ink(message)]
        fn register(&mut self, user: AccountId, data: Vec<u8>) {
            use scale::Decode;
            let token_id = u128::decode(&mut &data[..]).unwrap();
            assert!(
                self.erc721_owner_of(self.token, token_id as u32).unwrap_or(Some(AccountId::from([0x0;32]))) == Some(user),
                "SignUpTokenGatekeeper: this user does not own the token"
            );
            assert!(
                !self.registered_token_ids.get(token_id).unwrap_or(false),
                "SignUpTokenGatekeeper: this token has already been used to sign up"
            );
            self.registered_token_ids.insert(token_id, &true);
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
