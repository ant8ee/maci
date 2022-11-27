//! # Contracts instance  manager
//!
//! This is a Contract manager implementation.
//!

#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;
macro_rules! ensure {
    ( $condition:expr, $error:expr $(,)? ) => {{
        if !$condition {
            return ::core::result::Result::Err(::core::convert::Into::into($error));
        }
    }};
}
#[ink::contract]
pub mod contracts_manager {
    use ink_prelude::vec::Vec;
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use scale::{Decode, Encode};
    #[ink(storage)]
    #[derive(Default, SpreadAllocate)]
    pub struct ContractsManager {
        /// Mapping Hash to  Address
        hash_address: Mapping<Hash, AccountId>,
        signup_token_gatekeeper: AccountId,
        signup_token: AccountId,
        versatile_verifier: AccountId,
        free_for_all_signup_gatekeeper: AccountId,
        user_defined_initial_voice_credit_proxy: AccountId,
        constant_initial_voice_credit_proxy: AccountId,

        signup_token_gatekeeper_hash: Hash,
        free_for_all_signup_gatekeeper_hash: Hash,
        user_defined_initial_voice_credit_proxy_hash: Hash,
        constant_initial_voice_credit_proxy_hash: Hash,
        signup_token_hash: Hash,
        versatile_verifier_hash: Hash,
        endowment_amount: Balance,
        version: u32,
        /// The contract owner
        owner: AccountId,
    }
    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        OnlyOwner,
        TransactionFailed,
    }

    // The ContractsManager result types.
    pub type Result<T> = core::result::Result<T, Error>;

    impl ContractsManager {
        /// Creates a new contract.
        #[ink(constructor)]
        pub fn new() -> Self {
            // This call is required in order to correctly initialize the
            // `Mapping`s of our contract.
            ink_lang::utils::initialize_contract(|contract: &mut Self| {
                contract.owner = Self::env().caller();
                contract.version = 1;
                contract.endowment_amount = 0;
            })
        }
        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_signup_token_gatekeeper_contract(
            &mut self,
            code_hash: Hash,
            token: AccountId,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let salt = self.version.to_le_bytes();
                    let instance_params =
                        signup_token_gatekeeper::SignUpTokenGatekeeperRef::new(token)
                            .endowment(self.endowment_amount)
                            .code_hash(code_hash)
                            .salt_bytes(salt)
                            .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr = init_result
                        .expect("failed at instantiating the `signup_token_gatekeeper` contract");

                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            self.signup_token_gatekeeper = ans_contract_addr;
            self.hash_address.insert(&code_hash, &ans_contract_addr);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_free_for_all_signup_gatekeeper_contract(
            &mut self,
            code_hash: Hash,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let salt = self.version.to_le_bytes();
                    let instance_params =
                        free_for_all_signup_gatekeeper::FreeForAllSignupGatekeeperRef::new()
                            .endowment(self.endowment_amount)
                            .code_hash(code_hash)
                            .salt_bytes(salt)
                            .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr =
                        init_result.expect("failed at instantiating the `art factory ` contract");

                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            self.free_for_all_signup_gatekeeper = ans_contract_addr;
            self.hash_address.insert(&code_hash, &ans_contract_addr);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_user_defined_initial_voice_credit_proxy_contract(
            &mut self,
            code_hash: Hash,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let salt = self.version.to_le_bytes();
                    let instance_params = user_defined_initial_voice_credit_proxy::UserDefinedInitialVoiceCreditProxyRef::new()
                        .endowment(self.endowment_amount)
                        .code_hash(code_hash)
                        .salt_bytes(salt)
                        .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr = init_result
                        .expect("failed at instantiating the `art factory private` contract");

                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            self.user_defined_initial_voice_credit_proxy = ans_contract_addr;
            self.hash_address.insert(&code_hash, &ans_contract_addr);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_constant_initial_voice_credit_proxy_contract(
            &mut self,
            code_hash: Hash,
            balance: Balance,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let salt = self.version.to_le_bytes();
                    let instance_params = constant_initial_voice_credit_proxy::ConstantInitialVoiceCreditProxyRef::new(balance)
                        .endowment(self.endowment_amount)
                        .code_hash(code_hash)
                        .salt_bytes(salt)
                        .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr =
                        init_result.expect("failed at instantiating the `constant_initial_voice_credit_proxy` contract");
                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            self.constant_initial_voice_credit_proxy = ans_contract_addr;
            self.hash_address.insert(&code_hash, &ans_contract_addr);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_signup_token_contract(&mut self, code_hash: Hash) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let salt = self.version.to_le_bytes();
                    let instance_params = signup_token::SignupTokenRef::new()
                        .endowment(self.endowment_amount)
                        .code_hash(code_hash)
                        .salt_bytes(salt)
                        .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr =
                        init_result.expect("failed at instantiating the `signup_token` contract");

                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            self.signup_token = ans_contract_addr;
            self.hash_address.insert(&code_hash, &ans_contract_addr);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_versatile_verifier_contract(
            &mut self,
            code_hash: Hash,
            alpha1: Vec<Vec<u8>>,
            beta2: Vec<Vec<Vec<u8>>>,
            gamma2: Vec<Vec<Vec<u8>>>,
            delta2: Vec<Vec<Vec<u8>>>,
            ic: Vec<Vec<Vec<u8>>>,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let salt = self.version.to_le_bytes();
                    let instance_params = versatile_verifier::VersatileVerifierRef::new(
                        alpha1, beta2, gamma2, delta2, ic,
                    )
                    .endowment(self.endowment_amount)
                    .code_hash(code_hash)
                    .salt_bytes(salt)
                    .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr = init_result
                        .expect("failed at instantiating the `versatile_verifier` contract");

                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            self.versatile_verifier = ans_contract_addr;
            self.hash_address.insert(&code_hash, &ans_contract_addr);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        pub fn update_version(&mut self, version: u32) -> Result<()> {
            //onlyOwner
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);
            self.version = version;
            Ok(())
        }

        #[ink(message)]
        pub fn update_parameters(
            &mut self,
            signup_token_gatekeeper_hash: Hash,
            free_for_all_signup_gatekeeper_hash: Hash,
            user_defined_initial_voice_credit_proxy_hash: Hash,
            constant_initial_voice_credit_proxy_hash: Hash,
            signup_token_hash: Hash,
            versatile_verifier_hash: Hash,
        ) -> Result<()> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);
            self.signup_token_gatekeeper_hash = signup_token_gatekeeper_hash;
            self.free_for_all_signup_gatekeeper_hash = free_for_all_signup_gatekeeper_hash;
            self.user_defined_initial_voice_credit_proxy_hash =
                user_defined_initial_voice_credit_proxy_hash;
            self.constant_initial_voice_credit_proxy_hash =
                constant_initial_voice_credit_proxy_hash;
            self.signup_token_hash = signup_token_hash;
            self.versatile_verifier_hash = versatile_verifier_hash;
            Ok(())
        }
        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_contracts(
            &mut self,
            signup_token_gatekeeper_hash: Hash,
            free_for_all_signup_gatekeeper_hash: Hash,
            user_defined_initial_voice_credit_proxy_hash: Hash,
            constant_initial_voice_credit_proxy_hash: Hash,
            signup_token_hash: Hash,
            versatile_verifier_hash: Hash,
            balance: Balance,
            alpha1: Vec<Vec<u8>>,
            beta2: Vec<Vec<Vec<u8>>>,
            gamma2: Vec<Vec<Vec<u8>>>,
            delta2: Vec<Vec<Vec<u8>>>,
            ic: Vec<Vec<Vec<u8>>>,
        ) -> Result<()> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);
            let token = self.instantiate_signup_token_contract(signup_token_hash)?;
            self.instantiate_signup_token_gatekeeper_contract(signup_token_gatekeeper_hash, token)?;
            self.instantiate_versatile_verifier_contract(
                versatile_verifier_hash,
                alpha1,
                beta2,
                gamma2,
                delta2,
                ic,
            )?;
            self.instantiate_free_for_all_signup_gatekeeper_contract(
                free_for_all_signup_gatekeeper_hash,
            )?;
            self.instantiate_user_defined_initial_voice_credit_proxy_contract(
                user_defined_initial_voice_credit_proxy_hash,
            )?;
            self.instantiate_constant_initial_voice_credit_proxy_contract(
                constant_initial_voice_credit_proxy_hash,
                balance,
            )?;
            Ok(())
        }

        /// Querying signup_token_gatekeeper contract address
        /// # return signup_token_gatekeeper contract address
        #[ink(message)]
        pub fn signup_token_gatekeeper(&self) -> AccountId {
            self.signup_token_gatekeeper
        }
        /// Querying free_for_all_signup_gatekeeper contract address
        /// # return free_for_all_signup_gatekeeper contract address
        #[ink(message)]
        pub fn free_for_all_signup_gatekeeper(&self) -> AccountId {
            self.free_for_all_signup_gatekeeper
        }
        /// Querying constant_initial_voice_credit_proxy contract address
        /// # return constant_initial_voice_credit_proxy contract address
        #[ink(message)]
        pub fn constant_initial_voice_credit_proxy(&self) -> AccountId {
            self.constant_initial_voice_credit_proxy
        }
        /// Querying user_defined_initial_voice_credit_proxy contract address
        /// # return user_defined_initial_voice_credit_proxy contract address
        #[ink(message)]
        pub fn user_defined_initial_voice_credit_proxy(&self) -> AccountId {
            self.user_defined_initial_voice_credit_proxy
        }
        /// Querying signup_token contract address
        /// # return signup_token contract address
        #[ink(message)]
        pub fn signup_token(&self) -> AccountId {
            self.signup_token
        }
        /// Querying versatile_verifier contract address
        /// # return versatile_verifier contract address
        #[ink(message)]
        pub fn versatile_verifier(&self) -> AccountId {
            self.versatile_verifier
        }

        /// Querying signup_token_gatekeeper_hash
        /// # return signup_token_gatekeeper_hash
        #[ink(message)]
        pub fn signup_token_gatekeeper_hash(&self) -> Hash {
            self.signup_token_gatekeeper_hash
        }
        /// Querying free_for_all_signup_gatekeeper_hash
        /// # return free_for_all_signup_gatekeeper_hash
        #[ink(message)]
        pub fn free_for_all_signup_gatekeeper_hash(&self) -> Hash {
            self.free_for_all_signup_gatekeeper_hash
        }
        /// Querying constant_initial_voice_credit_proxy_hash
        /// # return constant_initial_voice_credit_proxy_hash
        #[ink(message)]
        pub fn constant_initial_voice_credit_proxy_hash(&self) -> Hash {
            self.constant_initial_voice_credit_proxy_hash
        }
        /// Querying user_defined_initial_voice_credit_proxy_hash
        /// # return user_defined_initial_voice_credit_proxy_hash
        #[ink(message)]
        pub fn user_defined_initial_voice_credit_proxy_hash(&self) -> Hash {
            self.user_defined_initial_voice_credit_proxy_hash
        }
        /// Querying signup_token_hash
        /// # return signup_token_hash
        #[ink(message)]
        pub fn signup_token_hash(&self) -> Hash {
            self.signup_token_hash
        }
        /// Querying versatile_verifier_hash
        /// # return versatile_verifier_hash
        #[ink(message)]
        pub fn versatile_verifier_hash(&self) -> Hash {
            self.versatile_verifier_hash
        }

        #[ink(message)]
        pub fn version(&self) -> u32 {
            self.version
        }
        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }
    }

    /// Unit tests
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;
        use ink_lang as ink;

        fn set_caller(sender: AccountId) {
            ink_env::test::set_caller::<ink_env::DefaultEnvironment>(sender);
        }
        fn default_accounts() -> ink_env::test::DefaultAccounts<Environment> {
            ink_env::test::default_accounts::<Environment>()
        }

        fn alice() -> AccountId {
            default_accounts().alice
        }

        fn bob() -> AccountId {
            default_accounts().bob
        }

        fn charlie() -> AccountId {
            default_accounts().charlie
        }

        fn init_contract() -> ContractsManager {
            let erc = ContractsManager::new();

            erc
        }
        #[ink::test]
        fn update_signup_token_works() {
            // Create a new contract instance.
            let mut contract_management = init_contract();
            let caller = alice();
            set_caller(caller);
            let signup_token = bob();
            assert!(contract_management
                .update_signup_token(signup_token)
                .is_ok());

            assert_eq!(contract_management.signup_token, signup_token);
        }
    }
}
