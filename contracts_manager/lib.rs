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
    use ink_prelude::{string::String, vec, vec::Vec};
    use ink_storage::{traits::SpreadAllocate, Mapping};
    use scale::{Decode, Encode};
    #[ink(storage)]
    #[derive(Default, SpreadAllocate)]
    pub struct ContractsManager {
        /// Mapping Hash to  Address
        hash_addresses: Mapping<Hash, Vec<AccountId>>,
        hashes: Vec<Hash>,
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
        pub fn instantiate_maci_contract(
            &mut self,
            code_hash: Hash,
            tree_depths: Vec<u8>,
            batch_sizes: Vec<u8>,
            max_values: Vec<u128>,
            sign_up_gatekeeper: AccountId,
            batch_ust_verifier: AccountId,
            qvt_verifier: AccountId,
            sign_up_duration_seconds: u128,
            voting_duration_seconds: u128,
            initial_voice_credit_proxy: AccountId,
            coordinator_pub_key: Vec<Vec<u8>>,
            coordinator_address: AccountId,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let mut salt: Vec<u8> = self.version.to_le_bytes().to_vec();
                    salt.extend(&tree_depths);
                    salt.extend(&batch_sizes);
                    let instance_params = maci::MaciRef::new(
                        tree_depths,
                        batch_sizes,
                        max_values,
                        sign_up_gatekeeper,
                        batch_ust_verifier,
                        qvt_verifier,
                        sign_up_duration_seconds,
                        voting_duration_seconds,
                        initial_voice_credit_proxy,
                        coordinator_pub_key,
                        coordinator_address,
                    )
                    .endowment(self.endowment_amount)
                    .code_hash(code_hash)
                    .salt_bytes(salt)
                    .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr =
                        init_result.expect("failed at instantiating the `maci` contract");

                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
            Ok(ans_contract_addr)
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
                    let mut salt: Vec<u8> = self.version.to_le_bytes().to_vec();
                    salt.extend(token.encode());
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
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
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
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
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
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
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
                    let mut salt: Vec<u8> = self.version.to_le_bytes().to_vec();
                    salt.extend(balance.encode());
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
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
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
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_versatile_verifier_contract(
            &mut self,
            code_hash: Hash,
            alpha1: Vec<String>,
            beta2: Vec<Vec<String>>,
            gamma2: Vec<Vec<String>>,
            delta2: Vec<Vec<String>>,
            ic: Vec<Vec<String>>,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let mut salt: Vec<u8> = self.version.to_le_bytes().to_vec();
                    salt.extend(alpha1.concat().bytes());
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
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
            Ok(ans_contract_addr)
        }

        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_quin_merkle_tree_contract(
            &mut self,
            code_hash: Hash,
            tree_levels: u8,
            version:u32,
        ) -> Result<AccountId> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);

            let instantiate_contract = || {
                #[cfg(test)]
                {
                    Ok(AccountId::from([0x0; 32]))
                }
                #[cfg(not(test))]
                {
                    let mut salt: Vec<u8> = version.to_le_bytes().to_vec();
                    salt.extend(tree_levels.concat().bytes());
                    let instance_params = quin_merkle_tree::QuinMerkleTreeRef::new(
                        tree_levels,
                    )
                    .endowment(self.endowment_amount)
                    .code_hash(code_hash)
                    .salt_bytes(salt)
                    .params();
                    let init_result = ink_env::instantiate_contract(&instance_params);
                    let contract_addr = init_result
                        .expect("failed at instantiating the `quin_merkle_tree` contract");

                    Ok(contract_addr)
                }
            };
            let ans_contract_addr = instantiate_contract()?;
            let mut hashes = self.hash_addresses.get(&code_hash).unwrap_or(Vec::new());
            hashes.push(ans_contract_addr);
            self.hash_addresses.insert(&code_hash, &hashes);
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
        pub fn update_hashes(
            &mut self,
            signup_token_gatekeeper_hash: Hash,
            free_for_all_signup_gatekeeper_hash: Hash,
            user_defined_initial_voice_credit_proxy_hash: Hash,
            constant_initial_voice_credit_proxy_hash: Hash,
            signup_token_hash: Hash,
            versatile_verifier_hash: Hash,
            maci: Hash,
        ) -> Result<()> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);
            self.hashes = vec![
                signup_token_gatekeeper_hash,
                free_for_all_signup_gatekeeper_hash,
                user_defined_initial_voice_credit_proxy_hash,
                constant_initial_voice_credit_proxy_hash,
                signup_token_hash,
                versatile_verifier_hash,
            ];
            Ok(())
        }
        #[ink(message)]
        #[cfg_attr(test, allow(unused_variables))]
        pub fn instantiate_contracts(
            &mut self,
            tree_depths: Vec<u8>,
            batch_sizes: Vec<u8>,
            max_values: Vec<u128>,
            sign_up_duration_seconds: u128,
            voting_duration_seconds: u128,
            coordinator_pub_key: Vec<Vec<u8>>,
            coordinator_address: AccountId,
            balance: Balance,
            alpha1: Vec<String>,
            beta2: Vec<Vec<String>>,
            gamma2: Vec<Vec<String>>,
            delta2: Vec<Vec<String>>,
            ic: Vec<Vec<String>>,
        ) -> Result<()> {
            ensure!(self.env().caller() == self.owner, Error::OnlyOwner);
            let token = self.instantiate_signup_token_contract(self.hashes[4])?;
            self.instantiate_signup_token_gatekeeper_contract(self.hashes[0], token)?;
            let gatekeeper =
                self.instantiate_free_for_all_signup_gatekeeper_contract(self.hashes[1])?;
            self.instantiate_user_defined_initial_voice_credit_proxy_contract(self.hashes[2])?;
            let proxy = self.instantiate_constant_initial_voice_credit_proxy_contract(
                self.hashes[3],
                balance,
            )?;
            let verifier = self.instantiate_versatile_verifier_contract(
                self.hashes[5],
                alpha1,
                beta2,
                gamma2,
                delta2,
                ic,
            )?;
            self.instantiate_maci_contract(
                self.hashes[6],
                tree_depths,
                batch_sizes,
                max_values,
                gatekeeper,
                verifier,
                verifier,
                sign_up_duration_seconds,
                voting_duration_seconds,
                proxy,
                coordinator_pub_key,
                coordinator_address,
            )?;
            Ok(())
        }

        /// Querying hashes
        /// # return hashes
        #[ink(message)]
        pub fn hashes(&self) -> Vec<Hash> {
            self.hashes.clone()
        }
        #[ink(message)]
        pub fn addresses_by_hash(&self, hash: Hash) -> Vec<AccountId> {
            self.hash_addresses.get(&hash).unwrap_or(Vec::new()).clone()
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
