#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;
mod library;
mod tree;
pub use crate::tree::quin_merkle_tree::QuinMerkleTree;

macro_rules! ensure {
    ( $condition:expr, $error:expr $(,)? ) => {{
        if !$condition {
            return ::core::result::Result::Err(::core::convert::Into::into($error));
        }
    }};
}
#[ink::contract]
mod maci {

    use super::*;

    use crate::library::{
        computeroot::ComputeRoot, domainobjs::DomainObjs, hasher::Hasher, verifytally::VerifyTally,
    };
    use crate::tree::hasher::Poseidon;
    use crate::tree::merkle_tree::{
        MerkleTree, MerkleTreeError, DEFAULT_ROOT_HISTORY_SIZE, MAX_DEPTH,
    };
    use crate::tree::quin_merkle_tree::MerkleTreeError as QuinMerkleTreeError;
    use hex_literal::hex;
    use ink_prelude::{vec, vec::Vec};
    use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout};

    // type PoseidonHash = [u8; 32];
    pub const SNARK_SCALAR_FIELD: &[u8] =
        b"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    const ZERO_VALUE: &[u8] =
        b"8370432830353022751713833565135785980866757267633941821328460903436894336785";

    #[derive(
        Default, PartialEq, scale::Decode, PackedLayout, SpreadLayout, SpreadAllocate, scale::Encode,
    )]
    #[cfg_attr(feature = "std", derive(Debug, ink_storage::traits::StorageLayout))]
    pub struct MultiMerkleTree {
        small_message_tree: Option<QuinMerkleTree<11, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        medium_message_tree: Option<QuinMerkleTree<13, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        large_message_tree: Option<QuinMerkleTree<15, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        l32_message_tree: Option<QuinMerkleTree<32, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        test_message_tree: Option<QuinMerkleTree<4, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        small_state_tree: Option<MerkleTree<8, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        medium_state_tree: Option<MerkleTree<9, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        large_state_tree: Option<MerkleTree<12, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        l32_state_tree: Option<MerkleTree<32, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        test_state_tree: Option<MerkleTree<4, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>>,
        tree_depth: u8,
    }

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
        /// The selector bytes that identifies the fn of the callee that should be called.
        pub iv: [u8; 32],
        /// The SCALE encoded parameters that are passed to the called fn.
        pub data: [[u8; 32]; 10],
    }

    #[derive(
        Default, scale::Decode, scale::Encode, Clone, SpreadAllocate, SpreadLayout, PackedLayout,
    )]
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
        /// The selector bytes that identifies the fn of the callee that should be called.
        pub x: [u8; 32],
        /// The SCALE encoded parameters that are passed to the called fn.
        pub y: [u8; 32],
    }

    #[derive(
        Default, scale::Decode, scale::Encode, Clone, SpreadAllocate, SpreadLayout, PackedLayout,
    )]
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

    #[ink(event)]
    pub struct SignUp {
        _user_pub_key: PubKey,
        _state_index: u128,
        voice_credit_balance: Balance,
    }
    #[ink(event)]
    pub struct PublishMessage {
        _message: Message,
        _enc_pub_key: PubKey,
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
        // The tree that tracks each user's public key and votes
        multi_tree: MultiMerkleTree,

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
        TransactionFailed,
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
        OnlyTheCoordinatorCanPublishMessagesInDebugMode,
        MessageLimitReached,
        OnlyTheCoordinatorCanSubmitSignupsInDebugMode,
        MaximumNumberOfSignupsReached,
        TooManyVoiceCredits,
        DepositFailure,
        MerkleTreeIsFull,
        MerkleTreeInvalidDepth,
        InvalidTransferredAmount,
        InvalidDepositSize,
        InsufficientFunds,
        NullifierAlreadyUsed,
        UnknownRoot,
    }
    impl From<MerkleTreeError> for Error {
        fn from(err: MerkleTreeError) -> Self {
            match err {
                MerkleTreeError::MerkleTreeIsFull => Error::MerkleTreeIsFull,
                MerkleTreeError::DepthTooLong => Error::MerkleTreeInvalidDepth,
                MerkleTreeError::DepthIsZero => Error::MerkleTreeInvalidDepth,
            }
        }
    }
    impl From<QuinMerkleTreeError> for Error {
        fn from(err: QuinMerkleTreeError) -> Self {
            match err {
                QuinMerkleTreeError::MerkleTreeIsFull => Error::MerkleTreeIsFull,
                QuinMerkleTreeError::DepthTooLong => Error::MerkleTreeInvalidDepth,
                QuinMerkleTreeError::DepthIsZero => Error::MerkleTreeInvalidDepth,
            }
        }
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
            ink::utils::initialize_contract(|se1f: &mut Self| {
                se1f.has_unprocessed_messages = true;
                se1f.coordinator_address = coordinator_address;
                se1f.tree_depths = tree_depths;
                se1f.tally_batch_size = batch_sizes[0];
                se1f.message_batch_size = batch_sizes[1];
                // Set the verifier contracts
                se1f.batch_ust_verifier = batch_ust_verifier;
                se1f.qvt_verifier = qvt_verifier;
                // Set the sign-up duration
                se1f.sign_up_timestamp = Self::env().block_timestamp() as u128;
                se1f.sign_up_duration_seconds = sign_up_duration_seconds;
                se1f.voting_duration_seconds = voting_duration_seconds;
                // Set the sign-up gatekeeper contract
                se1f.sign_up_gatekeeper = sign_up_gatekeeper;
                // Set the initial voice credit balance proxy
                se1f.initial_voice_credit_proxy = initial_voice_credit_proxy;
                // Set the coordinator's public key
                se1f.coordinator_pub_key = coordinator_pub_key; // [coordinator_pub_key.x,coordinator_pub_key.y];

                // Calculate and cache the max number of leaves for each tree.
                // They are used as public inputs to the batch update state tree snark.
                se1f.message_tree_max_leaf_index = 2u128.pow(tree_depths[1] as u32) - 1;

                // Check and store the maximum number of signups
                // It is the user's responsibility to ensure that the state tree depth
                // is just large enough and not more, or they will waste gas.
                let state_tree_max_leaf_index = 2u128.pow(tree_depths[0] as u32) - 1;
                se1f.max_users = max_values[0];
                // The maximum number of messages
                assert!(
                    max_values[0] <= state_tree_max_leaf_index
                        || max_values[1] <= se1f.message_tree_max_leaf_index,
                    "E10"
                );
                se1f.max_messages = max_values[1];
                // The maximum number of leaves, minus one, of meaningful vote options.
                // This allows the snark to do a no-op if the user votes for an option
                // which has no meaning attached to it
                se1f.vote_options_max_leaf_index = max_values[2];
                let mut result: [u8; 32] = Default::default();
                use ink_env::hash::CryptoHash;
                ink_env::hash::Blake2x256::hash(ZERO_VALUE, &mut result);
                se1f.multi_tree = MultiMerkleTree::new(tree_depths[0], result);
                // Calculate and store the empty vote option tree root. This value must
                // be set before we call hashedBlankStateLeaf() later
                se1f.empty_vote_option_tree_root =
                    Self::calc_empty_vote_option_tree_root(tree_depths[2]);
                // Calculate and store a commitment to 5 ** voteOptionTreeDepth zeros,
                // and a salt of 0.

                se1f.original_current_results_commitment =
                    Hasher::hash_left_right(se1f.empty_vote_option_tree_root, [0u8; 32]);

                se1f.current_results_commitment = se1f.original_current_results_commitment;
                se1f.original_spent_voice_credits_commitment =
                    Hasher::hash_left_right([0u8; 32], [0u8; 32]);

                se1f.current_spent_voice_credits_commitment =
                    se1f.original_spent_voice_credits_commitment;
                se1f.current_per_vo_spent_voice_credits_commitment =
                    se1f.original_current_results_commitment;

                // Compute the hash of a blank state leaf
                let h = Self::hashed_blank_state_leaf(se1f.empty_vote_option_tree_root);

                // Create the state tree
                // Make subsequent insertions start from leaf #1, as leaf #0 is only
                // updated with random data if a command is invalid.
                assert!(se1f.multi_tree.insert_state(h).is_ok());
            })
        }

        /*
         * Returns the deadline to sign up.
         */
        #[ink(message)]
        pub fn calc_sign_up_deadline(&self) -> u128 {
            self.sign_up_timestamp + self.sign_up_duration_seconds
        }

        /*
         * Ensures that the calling fn only continues execution if the
         * current block time is before the sign-up deadline.
         */
        fn is_before_sign_up_deadline(&self) -> Result<()> {
            if self.sign_up_duration_seconds != 0 {
                ensure!(
                    (self.env().block_timestamp() as u128) < self.calc_sign_up_deadline(),
                    Error::SignupPeriodPassed
                );
            }
            Ok(())
        }

        // /*
        //  * Ensures that the calling fn only continues execution if the
        //  * current block time is after or equal to the sign-up deadline.
        //  */
        // fn is_after_sign_up_deadline(&self) -> Result<()> {
        //     if self.sign_up_duration_seconds != 0 {
        //         ensure!(
        //             self.env().block_timestamp() as u128 >= self.calc_sign_up_deadline(),
        //             Error::SignupPeriodNotOver
        //         );
        //     }
        //     Ok(())
        // }

        /*
         * Returns the deadline to vote
         */
        #[ink(message)]
        pub fn calc_voting_deadline(&self) -> u128 {
            self.calc_sign_up_deadline() + self.voting_duration_seconds
        }

        /*
         * Ensures that the calling fn only continues execution if the
         * current block time is before the voting deadline.
         */
        fn is_before_voting_deadline(&self) -> Result<()> {
            if self.voting_duration_seconds != 0 {
                ensure!(
                    (self.env().block_timestamp() as u128) < self.calc_voting_deadline(),
                    Error::VotingPeriodPassed
                );
            }
            Ok(())
        }

        /*
         * Ensures that the calling fn only continues execution if the
         * current block time is after or equal to the voting deadline.
         */
        fn is_after_voting_deadline(&self) -> Result<()> {
            if self.voting_duration_seconds != 0 {
                ensure!(
                    self.env().block_timestamp() as u128 >= self.calc_voting_deadline(),
                    Error::VotingPeriodNotOver
                );
            }
            Ok(())
        }

        /*
         * Allows a user who is eligible to sign up to do so. The sign-up
         * gatekeeper will prevent double sign-ups or ineligible users from signing
         * up. This fn will only succeed if the sign-up deadline has not
         * passed. It also inserts a fresh state leaf into the state tree.
         * @param _user_pub_key The user's desired public key.
         * @param _sign_up_gatekeeper_data Data to pass to the sign-up gatekeeper's
         *     register() fn. For instance, the POAPGatekeeper or
         *     Sign_up_token_gatekeeper requires this value to be the ABI-encoded
         *     token ID.
         */
        #[ink(message)]
        pub fn sign_up(
            &mut self,
            _user_pub_key: PubKey,
            _sign_up_gatekeeper_data: Vec<u8>,
            _initial_voice_credit_proxy_data: Vec<u8>,
        ) -> Result<()> {
            self.is_before_sign_up_deadline()?;
            if self.sign_up_duration_seconds == 0 {
                ensure!(
                    self.env().caller() == self.coordinator_address,
                    Error::OnlyTheCoordinatorCanSubmitSignupsInDebugMode
                );
            }

            ensure!(
                self.num_sign_ups < self.max_users,
                Error::MaximumNumberOfSignupsReached
            );

            // Register the user via the sign-up gatekeeper. This fn should
            // throw if the user has already registered or if ineligible to do so.
            self.sign_up_gatekeeper_register(
                self.sign_up_gatekeeper,
                self.env().caller(),
                _sign_up_gatekeeper_data,
            )?;

            let voice_credit_balance = self.initial_voice_credit_proxy_get_voice_credits(
                self.initial_voice_credit_proxy,
                self.env().caller(),
                _initial_voice_credit_proxy_data,
            )?;

            // The limit on voice credits is 2 ^ 32 which is hardcoded into the
            // Update_state_tree circuit, specifically at check that there are
            // sufficient voice credits (using Greater_eq_than(32)).
            ensure!(
                voice_credit_balance <= 4294967296,
                Error::TooManyVoiceCredits
            );

            // Create, hash, and insert a fresh state leaf
            let state_leaf = StateLeaf {
                pub_key: _user_pub_key.clone(),
                vote_option_tree_root: self.empty_vote_option_tree_root,
                voice_credit_balance: Hasher::u128_to_bytes(voice_credit_balance),
                nonce: [0u8; 32],
            };

            let hashed_leaf = DomainObjs::hash_state_leaf(&state_leaf);

            // Insert the leaf
            self.multi_tree.insert_state(hashed_leaf)?;

            // Update a copy of the state tree root
            self.state_root = self.get_state_tree_root();

            self.num_sign_ups += 1;

            // num_sign_ups is equal to the state index of the leaf which was just
            // added to the state tree above
            self.env().emit_event(SignUp {
                _user_pub_key,
                _state_index: self.num_sign_ups,
                voice_credit_balance,
            });
            Ok(())
        }

        /*
         * Allows anyone to publish a message (an encrypted command and signature).
         * This fn also inserts it into the message tree.
         * @param _message The message to publish
         * @param _enc_pub_key An epheremal public key which can be combined with the
         *     coordinator's private key to generate an ECDH shared key which which was
         *     used to encrypt the message.
         */
        #[ink(message)]
        pub fn publish_message(&mut self, _message: Message, _enc_pub_key: PubKey) -> Result<()> {
            self.is_before_voting_deadline()?;
            if self.sign_up_duration_seconds == 0 {
                ensure!(
                    self.env().caller() == self.coordinator_address,
                    Error::OnlyTheCoordinatorCanPublishMessagesInDebugMode
                );
            }

            ensure!(
                self.num_messages < self.max_messages,
                Error::MessageLimitReached
            );

            // Calculate leaf value
            let leaf = DomainObjs::hash_message(&_message);

            // Insert the new leaf into the message tree
            self.multi_tree.insert_message(leaf)?;

            self.current_message_batch_index = (self.num_messages
                / self.message_batch_size as u128)
                * self.message_batch_size as u128;

            self.num_messages += 1;
            self.env().emit_event(PublishMessage {
                _message,
                _enc_pub_key,
            });
            Ok(())
        }

        /*
         * A helper fn to convert an array of 8 uint256 values into the a, b,
         * and c array values that the zk-SNARK verifier's verify_proof accepts.
         */
        #[ink(message)]
        pub fn unpack_proof(
            &self,
            _proof: [[u8; 32]; 8],
        ) -> ([[u8; 32]; 2], [[[u8; 32]; 2]; 2], [[u8; 32]; 2]) {
            (
                [_proof[0], _proof[1]],
                [[_proof[2], _proof[3]], [_proof[4], _proof[5]]],
                [_proof[6], _proof[7]],
            )
        }

        /*
         * A helper fn to create the public_signals array from meaningful
         * parameters.
         * @param _new_state_root The new state root after all messages are processed
         * @param _ecdh_pub_keys The public key used to generated the ECDH shared key
         *                     to decrypt the message
         */
        #[ink(message)]
        pub fn gen_batch_ust_public_signals(
            &self,
            _new_state_root: [u8; 32],
            _ecdh_pub_keys: Vec<PubKey>,
        ) -> Vec<[u8; 32]> {
            let message_batch_end_index = if self.current_message_batch_index
                + self.message_batch_size as u128
                <= self.num_messages
            {
                self.current_message_batch_index + self.message_batch_size as u128 - 1
            } else {
                self.num_messages - 1
            };
            let n = self.message_batch_size as usize;
            let mut public_signals = vec![[0u8; 32]; 12 + n * 3];
            public_signals[0] = _new_state_root;
            public_signals[1] = self.coordinator_pub_key.x;
            public_signals[2] = self.coordinator_pub_key.y;
            public_signals[3] = Hasher::u128_to_bytes(self.vote_options_max_leaf_index);
            public_signals[4] = self.multi_tree.get_last_root_of_message();
            public_signals[5] = Hasher::u128_to_bytes(self.current_message_batch_index);
            public_signals[6] = Hasher::u128_to_bytes(message_batch_end_index);
            public_signals[7] = Hasher::u128_to_bytes(self.num_sign_ups);

            for i in 0..n {
                let x = 8 + i * 2;
                let y = x + 1;
                public_signals[x] = _ecdh_pub_keys[i].x;
                public_signals[y] = _ecdh_pub_keys[i].y;
            }

            public_signals
        }

        /*
         * Update the state_root if the batch update state root proof is
         * valid.
         * @param _new_state_root The new state root after all messages are processed
         * @param _ecdh_pub_keys The public key used to generated the ECDH shared key
         *                     to decrypt the message
         * @param _proof The zk-SNARK proof
         */
        #[ink(message)]
        pub fn batch_process_message(
            &mut self,
            _new_state_root: [u8; 32],
            _ecdh_pub_keys: Vec<PubKey>,
            _proof: [[u8; 32]; 8],
        ) -> Result<()> {
            self.is_after_voting_deadline()?;

            // Ensure that the current batch index is within range
            ensure!(self.has_unprocessed_messages, Error::NoMoreMessages);

            ensure!(
                _ecdh_pub_keys.len() as u8 == self.message_batch_size,
                Error::InvalidEcdhPubkeysLength
            );

            // Ensure that current_message_batch_index is within range
            ensure!(
                self.current_message_batch_index <= self.message_tree_max_leaf_index,
                Error::CurrentMessageBatchOutOfRange
            );

            // Assemble the public inputs to the snark
            let public_signals = self.gen_batch_ust_public_signals(_new_state_root, _ecdh_pub_keys);

            // Ensure that each public input is within range of the snark scalar
            // field.
            // TODO: consider having more granular revert reasons
            // TODO: this check is already performed in the verifier contract
            for public_signal in &public_signals {
                ensure!(
                    public_signal < SNARK_SCALAR_FIELD.try_into().unwrap(),
                    Error::PublicSignalTooLarge
                );
            }

            // Unpack the snark proof
            let (a, b, c) = self.unpack_proof(_proof);

            // Verify the proof
            ensure!(
                self.batch_ust_verifier_verify_proof(
                    self.batch_ust_verifier,
                    a,
                    b,
                    c,
                    public_signals
                ),
                Error::InvalidBatchUstProof
            );

            // Increase the message batch start index to ensure that each message
            // batch is processed in order
            if self.current_message_batch_index == 0 {
                self.has_unprocessed_messages = false;
            } else {
                self.current_message_batch_index -= self.message_batch_size as u128;
            }

            // Update the state root
            self.state_root = _new_state_root;
            if self.state_root_before_processing == [0u8; 32] {
                self.state_root_before_processing = self.state_root;
            }
            Ok(())
        }

        /*
         * Returns the public signals required to verify a quadratic vote tally
         * snark.
         */
        #[ink(message)]
        pub fn gen_qvt_public_signals(
            &self,
            _intermediate_state_root: [u8; 32],
            _new_results_commitment: [u8; 32],
            _new_spent_voice_credits_commitment: [u8; 32],
            _new_per_vo_spent_voice_credits_commitment: [u8; 32],
            _total_votes: u128,
        ) -> Vec<[u8; 32]> {
            let current_qvt_batch_num = Hasher::u128_to_bytes(self.current_qvt_batch_num);
            let total_votes = Hasher::u128_to_bytes(_total_votes);
            vec![
                _new_results_commitment,
                _new_spent_voice_credits_commitment,
                _new_per_vo_spent_voice_credits_commitment,
                total_votes,
                self.state_root,
                current_qvt_batch_num,
                _intermediate_state_root,
                self.current_results_commitment,
                self.current_spent_voice_credits_commitment,
                self.current_per_vo_spent_voice_credits_commitment,
            ]
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
        #[ink(message)]
        pub fn has_untallied_state_leaves(&self) -> bool {
            self.current_qvt_batch_num < (1 + (self.num_sign_ups / self.tally_batch_size as u128))
        }

        /*
         * Tally the next batch of state leaves.
         * @param _intermediate_state_root The intermediate state root, which is
         *     generated from the current batch of state leaves
         * @param _new_results_commitment A hash of the tallied results so far
         *     (cumulative)
         * @param _proof The zk-SNARK proof
         */
        #[ink(message)]
        pub fn prove_vote_tally_batch(
            &mut self,
            _intermediate_state_root: [u8; 32],
            _new_results_commitment: [u8; 32],
            _new_spent_voice_credits_commitment: [u8; 32],
            _new_per_vo_spent_voice_credits_commitment: [u8; 32],
            _total_votes: u128,
            _proof: [[u8; 32]; 8],
        ) -> Result<()> {
            ensure!(self.num_sign_ups > 0, Error::NoSignups);
            let total_batches = 1 + (self.num_sign_ups / self.tally_batch_size as u128);

            // Ensure that the batch # is within range
            ensure!(
                self.current_qvt_batch_num < total_batches,
                Error::AllBatchesTallied
            );

            // Generate the public signals
            // public 'input' signals = [output signals, public inputs]
            let public_signals = self.gen_qvt_public_signals(
                _intermediate_state_root,
                _new_results_commitment,
                _new_spent_voice_credits_commitment,
                _new_per_vo_spent_voice_credits_commitment,
                _total_votes,
            );

            // Ensure that each public input is within range of the snark scalar
            // field.
            // TODO: consider having more granular revert reasons
            for public_signal in &public_signals {
                ensure!(
                    public_signal < SNARK_SCALAR_FIELD.try_into().unwrap(),
                    Error::PublicSignalTooLarge
                );
            }

            // Unpack the snark proof
            let (a, b, c) = self.unpack_proof(_proof);

            // Verify the proof
            let is_valid =
                self.qvt_verifier_verify_proof(self.qvt_verifier, a, b, c, public_signals);

            ensure!(is_valid == true, Error::InvalidTallyProof);

            // Save the commitment to the new results for the next batch
            self.current_results_commitment = _new_results_commitment;

            // Save the commitment to the total spent voice credits for the next batch
            self.current_spent_voice_credits_commitment = _new_spent_voice_credits_commitment;

            // Save the commitment to the per voice credit spent voice credits for the next batch
            self.current_per_vo_spent_voice_credits_commitment =
                _new_per_vo_spent_voice_credits_commitment;

            // Save the total votes
            self.total_votes = _total_votes;

            // Increment the batch #
            self.current_qvt_batch_num += 1;
            Ok(())
        }

        /*
         * Reset the storage variables which change during message processing and
         * vote tallying. Does not affect any signups or messages. This is useful
         * if the client-side process/tally code has a bug that causes an invalid
         * state transition.
         */
        #[ink(message)]
        pub fn coordinator_reset(&mut self) -> Result<()> {
            ensure!(
                self.env().caller() == self.coordinator_address,
                Error::OnlyCoordinator
            );
            let message_batch_size = self.message_batch_size as u128;
            self.has_unprocessed_messages = true;
            self.state_root = self.state_root_before_processing;
            self.current_message_batch_index = if self.num_messages % message_batch_size == 0 {
                self.num_messages - message_batch_size
            } else {
                (self.num_messages / message_batch_size) * message_batch_size
            };
            self.current_qvt_batch_num = 0;

            self.current_results_commitment = self.original_current_results_commitment;
            self.current_spent_voice_credits_commitment =
                self.original_spent_voice_credits_commitment;
            self.current_per_vo_spent_voice_credits_commitment =
                self.original_current_results_commitment;

            self.total_votes = 0;
            Ok(())
        }

        /*
         * Verify the result of the vote tally using a Merkle proof and the salt.
         */
        #[ink(message)]
        pub fn verify_tally_result(
            &self,
            _depth: u8,
            _index: u128,
            _leaf: [u8; 32],
            _path_elements: Vec<Vec<[u8; 32]>>,
            _salt: [u8; 32],
        ) -> bool {
            let computed_root =
                VerifyTally::compute_merkle_root_from_path(_depth, _index, _leaf, _path_elements);

            self.current_results_commitment == Hasher::hash_left_right(computed_root, _salt)
        }

        /*
         * Verify the number of voice credits spent for a particular vote option
         * using a Merkle proof and the salt.
         */
        #[ink(message)]
        pub fn verify_per_vo_spent_voice_credits(
            &self,
            _depth: u8,
            _index: u128,
            _leaf: [u8; 32],
            _path_elements: Vec<Vec<[u8; 32]>>,
            _salt: [u8; 32],
        ) -> bool {
            let computed_root =
                VerifyTally::compute_merkle_root_from_path(_depth, _index, _leaf, _path_elements);

            self.current_per_vo_spent_voice_credits_commitment
                == Hasher::hash_left_right(computed_root, _salt)
        }

        /*
         * Verify the total number of spent voice credits.
         * @param _spent The value to verify
         * @param _salt The salt which is hashed with the value to generate the
         *              commitment to the spent voice credits.
         */
        #[ink(message)]
        pub fn verify_spent_voice_credits(&self, _spent: [u8; 32], _salt: [u8; 32]) -> bool {
            self.current_spent_voice_credits_commitment == Hasher::hash_left_right(_spent, _salt)
        }
        fn calc_empty_vote_option_tree_root(levels: u8) -> [u8; 32] {
            ComputeRoot::compute_empty_quin_root(levels, [0u8; 32])
        }
        #[ink(message)]
        pub fn get_message_tree_root(&self) -> [u8; 32] {
            self.multi_tree.get_last_root_of_message()
        }
        #[ink(message)]
        pub fn get_state_tree_root(&self) -> [u8; 32] {
            self.multi_tree.get_last_root_of_state()
        }
    }
    #[ink(impl)]
    impl Maci {
        #[cfg_attr(test, allow(unused_variables))]
        fn sign_up_gatekeeper_register(
            &mut self,
            contract_address: AccountId,
            user: AccountId,
            data: Vec<u8>,
        ) -> Result<()> {
            #[cfg(test)]
            {
                Ok(())
            }
            #[cfg(not(test))]
            {
                use ink_env::call::{build_call, Call, ExecutionInput};
                let selector: [u8; 4] = ink_lang::selector_bytes!("register");
                let (gas_limit, transferred_value) = (0, 0);
                build_call::<<Self as ::ink_lang::reflect::ContractEnv>::Env>()
                    .call_type(
                        Call::new()
                            .callee(contract_address)
                            .gas_limit(gas_limit)
                            .transferred_value(transferred_value),
                    )
                    .exec_input(
                        ExecutionInput::new(selector.into())
                            .push_arg(user)
                            .push_arg(data),
                    )
                    .returns::<()>()
                    .fire()
                    .map_err(|e| {
                        ink_env::debug_println!("sign_up_gatekeeper_register= {:?}", e);
                        Error::TransactionFailed
                    })
            }
        }
        #[cfg_attr(test, allow(unused_variables))]
        fn initial_voice_credit_proxy_get_voice_credits(
            &mut self,
            contract_address: AccountId,
            user: AccountId,
            data: Vec<u8>,
        ) -> Result<Balance> {
            #[cfg(test)]
            {
                Ok(0)
            }
            #[cfg(not(test))]
            {
                use ink_env::call::{build_call, Call, ExecutionInput};
                let selector: [u8; 4] = ink_lang::selector_bytes!("get_voice_credits");
                let (gas_limit, transferred_value) = (0, 0);
                build_call::<<Self as ::ink_lang::reflect::ContractEnv>::Env>()
                    .call_type(
                        Call::new()
                            .callee(contract_address)
                            .gas_limit(gas_limit)
                            .transferred_value(transferred_value),
                    )
                    .exec_input(
                        ExecutionInput::new(selector.into())
                            .push_arg(user)
                            .push_arg(data),
                    )
                    .returns::<Balance>()
                    .fire()
                    .map_err(|e| {
                        ink_env::debug_println!(
                            "initial_voice_credit_proxy_get_voice_credits= {:?}",
                            e
                        );
                        Error::TransactionFailed
                    })
            }
        }
        #[cfg_attr(test, allow(unused_variables))]
        fn batch_ust_verifier_verify_proof(
            &self,
            contract_address: AccountId,
            a: [[u8; 32]; 2],
            b: [[[u8; 32]; 2]; 2],
            c: [[u8; 32]; 2],
            input: Vec<[u8; 32]>,
        ) -> bool {
            #[cfg(test)]
            {
                true
            }
            #[cfg(not(test))]
            {
                use ink_env::call::{build_call, Call, ExecutionInput};
                let selector: [u8; 4] = ink_lang::selector_bytes!("verify_proof");
                let (gas_limit, transferred_value) = (0, 0);
                build_call::<<Self as ::ink_lang::reflect::ContractEnv>::Env>()
                    .call_type(
                        Call::new()
                            .callee(contract_address)
                            .gas_limit(gas_limit)
                            .transferred_value(transferred_value),
                    )
                    .exec_input(
                        ExecutionInput::new(selector.into())
                            .push_arg(a)
                            .push_arg(b)
                            .push_arg(c)
                            .push_arg(input),
                    )
                    .returns::<bool>()
                    .fire()
                    .map_err(|e| {
                        ink_env::debug_println!("batch_ust_verifier_verify_proof= {:?}", e);
                        Error::TransactionFailed
                    })
                    .unwrap_or(false)
            }
        }
        #[cfg_attr(test, allow(unused_variables))]
        fn qvt_verifier_verify_proof(
            &self,
            contract_address: AccountId,
            a: [[u8; 32]; 2],
            b: [[[u8; 32]; 2]; 2],
            c: [[u8; 32]; 2],
            input: Vec<[u8; 32]>,
        ) -> bool {
            #[cfg(test)]
            {
                true
            }
            #[cfg(not(test))]
            {
                use ink_env::call::{build_call, Call, ExecutionInput};
                let selector: [u8; 4] = ink_lang::selector_bytes!("verify_proof");
                let (gas_limit, transferred_value) = (0, 0);
                build_call::<<Self as ::ink_lang::reflect::ContractEnv>::Env>()
                    .call_type(
                        Call::new()
                            .callee(contract_address)
                            .gas_limit(gas_limit)
                            .transferred_value(transferred_value),
                    )
                    .exec_input(
                        ExecutionInput::new(selector.into())
                            .push_arg(a)
                            .push_arg(b)
                            .push_arg(c)
                            .push_arg(input),
                    )
                    .returns::<bool>()
                    .fire()
                    .map_err(|e| {
                        ink_env::debug_println!("qvt_verifier_verify_proof= {:?}", e);
                        Error::TransactionFailed
                    })
                    .unwrap_or(false)
            }
        }
    }
    impl MultiMerkleTree {
        fn new(state_tree_depth: u8, zero_value: [u8; 32]) -> Self {
            let mut tree = Self::default();
            tree.tree_depth = state_tree_depth;
            match state_tree_depth {
                1..=4 => {
                    tree.test_message_tree = Some(
                        QuinMerkleTree::<4, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new(zero_value)
                            .unwrap(),
                    );
                    tree.test_state_tree =
                        Some(MerkleTree::<4, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap());
                }
                5..=11 => {
                    tree.small_message_tree = Some(
                        QuinMerkleTree::<11, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new(zero_value)
                            .unwrap(),
                    );
                    tree.small_state_tree =
                        Some(MerkleTree::<8, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap());
                }
                12..=13 => {
                    tree.medium_message_tree = Some(
                        QuinMerkleTree::<13, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new(zero_value)
                            .unwrap(),
                    );
                    tree.medium_state_tree =
                        Some(MerkleTree::<9, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap());
                }
                14..=15 => {
                    tree.large_message_tree = Some(
                        QuinMerkleTree::<15, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new(zero_value)
                            .unwrap(),
                    );
                    tree.large_state_tree =
                        Some(MerkleTree::<12, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap());
                }
                _ => {
                    tree.l32_message_tree = Some(
                        QuinMerkleTree::<32, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new(zero_value)
                            .unwrap(),
                    );
                    tree.l32_state_tree =
                        Some(MerkleTree::<32, DEFAULT_ROOT_HISTORY_SIZE, Poseidon>::new().unwrap());
                }
            }
            tree
        }

        fn insert_message(&mut self, leaf: [u8; 32]) -> Result<()> {
            match self.tree_depth {
                1..=4 => self.test_message_tree.as_mut().unwrap().insert(leaf)?,
                5..=11 => self.small_message_tree.as_mut().unwrap().insert(leaf)?,
                12..=13 => self.medium_message_tree.as_mut().unwrap().insert(leaf)?,
                14..=15 => self.large_message_tree.as_mut().unwrap().insert(leaf)?,
                _ => self.l32_message_tree.as_mut().unwrap().insert(leaf)?,
            };
            Ok(())
        }

        fn insert_state(&mut self, leaf: [u8; 32]) -> Result<()> {
            match self.tree_depth {
                1..=4 => self.test_state_tree.as_mut().unwrap().insert(leaf)?,
                5..=11 => self.small_state_tree.as_mut().unwrap().insert(leaf)?,
                12..=13 => self.medium_state_tree.as_mut().unwrap().insert(leaf)?,
                14..=15 => self.large_state_tree.as_mut().unwrap().insert(leaf)?,
                _ => self.l32_state_tree.as_mut().unwrap().insert(leaf)?,
            };
            Ok(())
        }

        fn get_last_root_of_message(&self) -> [u8; 32] {
            match self.tree_depth {
                1..=4 => self.test_message_tree.as_ref().unwrap().get_last_root(),
                5..=11 => self.small_message_tree.as_ref().unwrap().get_last_root(),
                12..=13 => self.medium_message_tree.as_ref().unwrap().get_last_root(),
                14..=15 => self.large_message_tree.as_ref().unwrap().get_last_root(),
                _ => self.l32_message_tree.as_ref().unwrap().get_last_root(),
            }
        }

        fn get_last_root_of_state(&self) -> [u8; 32] {
            match self.tree_depth {
                1..=4 => self.test_state_tree.as_ref().unwrap().get_last_root(),
                5..=11 => self.small_state_tree.as_ref().unwrap().get_last_root(),
                12..=13 => self.medium_state_tree.as_ref().unwrap().get_last_root(),
                14..=15 => self.large_state_tree.as_ref().unwrap().get_last_root(),
                _ => self.l32_state_tree.as_ref().unwrap().get_last_root(),
            }
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

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {
            // let mut maci = Maci::new(false);
        }
    }
}
