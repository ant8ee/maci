#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;
mod library;
mod tree;
#[ink::contract]
mod maci {

    use super::*;

   use ink_storage::{
        traits::{PackedAllocate, PackedLayout, SpreadAllocate, SpreadLayout},
        Mapping,
    };
use hex_literal::hex;

    use crate::library::{
        computeroot::ComputeRoot, domainobjs::DomainObjs,
        hasher::Hasher,poseidon::PoseidonT3
    };
    use crate::tree::hasher::Poseidon;
    use crate::tree::merkle_tree::{
        MerkleTree, MerkleTreeError, DEFAULT_ROOT_HISTORY_SIZE, MAX_DEPTH,
    };

    type PoseidonHash = [u8; 32];

    #[derive(scale::Decode, scale::Encode)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct Message {
        /// The selector bytes that identifies the function of the callee that should be called.
        pub iv: [u8; 32],
        /// The SCALE encoded parameters that are passed to the called function.
        pub data: [[u8; 32]; 10],
    }

    #[derive(Default,scale::Decode, scale::Encode,Clone,SpreadAllocate,SpreadLayout,PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct PubKey {
        /// The selector bytes that identifies the function of the callee that should be called.
        pub x: [u8; 32],
        /// The SCALE encoded parameters that are passed to the called function.
        pub y: [u8; 32],
    }

    #[derive(Default,scale::Decode, scale::Encode,Clone,SpreadAllocate,SpreadLayout,PackedLayout)]
    #[cfg_attr(
        feature = "std",
        derive(
            Debug,
            PartialEq,
            Eq,
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout
        )
    )]
    pub struct StateLeaf {
        pub pub_key: PubKey,
        pub vote_option_tree_root: [u8; 32],
        pub voice_credit_balance: [u8; 32],
        pub nonce: [u8; 32],
    }

    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    #[derive(ink_storage::traits::SpreadAllocate)]
    pub struct Maci {
        // Verifier Contracts
        batch_ust_verifier: AccountId,
        qvt_verifier: AccountId,

        // The number of messages which the batch update state tree snark can
        // process per batch
        message_batch_size: u8,

        // The number of state leaves to tally per batch via the vote tally snark
        tally_batch_size: u8,

        // The tree that tracks the sign-up messages.
        message_tree: MerkleTree<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>,

        // The tree that tracks each user's public key and votes
        state_tree: MerkleTree<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>,

        original_spent_voice_credits_commitment: [u8; 32],
        original_current_results_commitment: [u8; 32],

        // To store the Merkle root of a tree with 5 **
        // _tree_depths.vote_option_tree_depth leaves of value 0
        empty_vote_option_tree_root: [u8; 32],

        // The maximum number of leaves, minus one, of meaningful vote options.
        vote_options_max_leaf_index: u128,

        // The total sum of votes
        total_votes: u128,

        // Cached results of 2 ** depth - 1 where depth is the state tree depth and
        // message tree depth
        message_tree_max_leaf_index: u128,

        // The maximum number of signups allowed
        max_users: u128,

        // The maximum number of messages allowed
        max_messages: u128,

        // When the contract was deployed. We assume that the signup period starts
        // immediately upon deployment.
        sign_up_timestamp: u128,

        // Duration of the sign-up and voting periods, in seconds. If these values
        // are set to 0, the contract will be in debug mode - that is, only the
        // coordinator may sign up and publish messages. This makes it possible to
        // submit a large number of signups and messages without having to do so
        // before the signup and voting deadlines.
        sign_up_duration_seconds: u128,
        voting_duration_seconds: u128,

        // Address of the Sign_up_gatekeeper, a contract which determines whether a
        // user may sign up to vote
        sign_up_gatekeeper: AccountId,

        // The contract which provides the values of the initial voice credit
        // balance per user
        initial_voice_credit_proxy: AccountId,
        // The coordinator's public key
        coordinator_pub_key: PubKey,
        num_sign_ups: u128,
        num_messages: u128,

        tree_depths: [u8; 3],

        has_unprocessed_messages: bool,

        coordinator_address: AccountId,

        //----------------------
        // Storage variables that can be reset by coordinatorReset()

        // The Merkle root of the state tree after each signup. Note that
        // batchProcessMessage() will not update the state tree. Rather, it will
        // directly update stateRoot if given a valid proof and public signals.
        state_root: [u8; 32],
        state_root_before_processing: [u8; 32],

        // The current message batch index
        current_message_batch_index: u128,

        // The batch # for prove_vote_tally_batch
        current_qvt_batch_num: u128,

        // To store hash_left_right(Merkle root of 5 ** vote_option_tree_depth zeros, 0)
        current_results_commitment: [u8; 32],

        // To store hash_left_right(0, 0). We precompute it here to save gas.
        current_spent_voice_credits_commitment: [u8; 32],

        // To store hash_left_right(Merkle root of 5 ** vote_option_tree_depth zeros, 0)
        current_per_vo_spent_voice_credits_commitment: [u8; 32],
    }

    /// Errors which my be returned from the smart contract
    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        PublicSignalTooLarge,
        InvalidBatchUstProof,
        InvalidTallyProof,
        OnlyCoordinator,
        AllBatchesTallied,
        CurrentMessageBatchOutOfRange,
        NoSignups,
        InvalidEcdhPubkeysLength,
        NoMoreMessages,
        InvalidMaxUsersOrMessages,
        SignupPeriodPassed,
        SignupPeriodNotOver,
        VotingPeriodPassed,
        VotingPeriodNotOver,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Maci {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(
            tree_depths: [u8; 3],
            batch_sizes: [u8; 2],
            max_values: [u128; 3],
            sign_up_gatekeeper: AccountId,
            batch_ust_verifier: AccountId,
            qvt_verifier: AccountId,
            sign_up_duration_seconds: u128,
            voting_duration_seconds: u128,
            initial_voice_credit_proxy: AccountId,
            coordinator_pub_key: PubKey,
            coordinator_address: AccountId,
        ) -> Self {
            ink::utils::initialize_contract(|_self: &mut Self| {
                _self.coordinator_address = coordinator_address;
                _self.tree_depths = tree_depths;
                _self.tally_batch_size = batch_sizes[0];
                _self.message_batch_size = batch_sizes[1];
                // Set the verifier contracts
                _self.batch_ust_verifier = batch_ust_verifier;
                _self.qvt_verifier = qvt_verifier;
                // Set the sign-up duration
                _self.sign_up_timestamp = Self::env().block_timestamp() as u128;
                _self.sign_up_duration_seconds = sign_up_duration_seconds;
                _self.voting_duration_seconds = voting_duration_seconds;
                // Set the sign-up gatekeeper contract
                _self.sign_up_gatekeeper = sign_up_gatekeeper;
                // Set the initial voice credit balance proxy
                _self.initial_voice_credit_proxy = initial_voice_credit_proxy;
                // Set the coordinator's public key
                _self.coordinator_pub_key =coordinator_pub_key;// [coordinator_pub_key.x,coordinator_pub_key.y];

                // Calculate and cache the max number of leaves for each tree.
                // They are used as public inputs to the batch update state tree snark.
                _self.message_tree_max_leaf_index = 2u128.pow(tree_depths[1] as u32) - 1;

                // Check and store the maximum number of signups
                // It is the user's responsibility to ensure that the state tree depth
                // is just large enough and not more, or they will waste gas.
                let state_tree_max_leaf_index = 2u128.pow(tree_depths[0] as u32) - 1;
                _self.max_users = max_values[0];
                // The maximum number of messages
                assert!(
                    max_values[0] <= state_tree_max_leaf_index
                        || max_values[1] <= _self.message_tree_max_leaf_index,
                    "E10"
                );
                _self.max_messages = max_values[1];
                // The maximum number of leaves, minus one, of meaningful vote options.
                // This allows the snark to do a no-op if the user votes for an option
                // which has no meaning attached to it
                _self.vote_options_max_leaf_index = max_values[2];
                _self.message_tree =
                    MerkleTree::<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap();
                // Calculate and store the empty vote option tree root. This value must
                // be set before we call hashedBlankStateLeaf() later
                _self.empty_vote_option_tree_root =
                    Self::calc_empty_vote_option_tree_root(tree_depths[2]);
                // Calculate and store a commitment to 5 ** voteOptionTreeDepth zeros,
                // and a salt of 0.

                _self.original_current_results_commitment =
                     Hasher::hash_left_right(_self.empty_vote_option_tree_root, [0u8;32]);

                _self.current_results_commitment = _self.original_current_results_commitment;
                _self.original_spent_voice_credits_commitment = Hasher::hash_left_right([0u8;32], [0u8;32]);

                _self.current_spent_voice_credits_commitment =
                    _self.original_spent_voice_credits_commitment;
                _self.current_per_vo_spent_voice_credits_commitment =
                    _self.original_current_results_commitment;

                // Compute the hash of a blank state leaf
                let h = Self::hashed_blank_state_leaf(_self.empty_vote_option_tree_root);

                // Create the state tree
                _self.state_tree =
                    MerkleTree::<MAX_DEPTH, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap();
                // Make subsequent insertions start from leaf #1, as leaf #0 is only
                // updated with random data if a command is invalid.
                _self.state_tree.insert(h);
            })
        }

        /// A message that can be called on instantiated contracts.
        /// This one flips the value of the stored `bool` from `true`
        /// to `false` and vice versa.
        #[ink(message)]
        pub fn flip(&mut self) {
            // self.value = !self.value;
        }

        /// Simply returns the current value of our `bool`.
        #[ink(message)]
        pub fn get(&self) -> [u8; 32] {
            PoseidonT3::poseidon([[0u8; 32]; 2])
        }
        fn hashed_blank_state_leaf(empty_vote_option_tree_root: [u8; 32]) -> [u8; 32] {
            // The pubkey is the first Pedersen base point from iden3's circomlib
            let state_leaf = StateLeaf {
                pub_key: PubKey {
                    x: hex!("171e826ad4a870fd925e0bf0e87884e70e080879c2205ef10114f28a3b6f6dd7"),
                    y: hex!("2bd407d897fbbca9f88adfd2d15252e69de8c1564eb4d3d27162e259172f1a1d"),
                },
                vote_option_tree_root: empty_vote_option_tree_root,
                voice_credit_balance: [0u8; 32],
                nonce: [0u8; 32],
            };

            DomainObjs::hash_state_leaf(&state_leaf)
        }
        fn calc_empty_vote_option_tree_root(levels: u8) -> [u8; 32] {
            ComputeRoot::compute_empty_quin_root(levels, [0u8; 32])
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
        fn default_works() {
            let maci = Maci::default();
            assert_eq!(maci.get(), [0u8; 32]);
        }

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {
            let mut maci = Maci::new(false);
            assert_eq!(maci.get(), [0u8; 32]);
            maci.flip();
            assert_eq!(maci.get(), [0u8; 32]);
        }
    }
}
