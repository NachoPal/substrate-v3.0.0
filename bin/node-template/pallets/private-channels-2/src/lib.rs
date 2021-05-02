#![cfg_attr(not(feature = "std"), no_std)]
use sp_std::prelude::*;
use sp_application_crypto::RuntimeAppPublic;
use frame_system::{
	self as system,
	ensure_signed,
	ensure_none,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendUnsignedTransaction, SendSignedTransaction,
		SignedPayload, SigningTypes, Signer, SubmitTransaction,
	}
};
use frame_support::{
	debug, Parameter,
	dispatch::DispatchResult, decl_module, decl_storage, decl_event, decl_error,
	traits::{Get, UnfilteredDispatchable},
	weights::{GetDispatchInfo},
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain::{http, Duration, storage::StorageValueRef},
	traits::{Member, Zero},
	transaction_validity::{
		InvalidTransaction, ValidTransaction, TransactionValidity, TransactionSource,
		TransactionPriority,
	},
};
use codec::{Encode, Decode};
use sp_std::vec::Vec;
// use sodiumoxide::crypto::box_::{Nonce};

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"priv");

pub mod ed25519 {
	mod app_ed25519 {
		use super::super::KEY_TYPE;
		use sp_application_crypto::{app_crypto, key_types::IM_ONLINE, ed25519};
		app_crypto!(ed25519, KEY_TYPE);
	}

	sp_application_crypto::with_pair! {
		/// An i'm online keypair using ed25519 as its crypto.
		pub type AuthorityPair = app_ed25519::Pair;
	}

	/// An i'm online signature using ed25519 as its crypto.
	pub type AuthoritySignature = app_ed25519::Signature;

	/// An i'm online identifier using ed25519 as its crypto.
	pub type AuthorityId = app_ed25519::Public;
}

/// This pallet's configuration trait
pub trait Config: frame_system::Config {
	/// The identifier type for an authority.
	type AuthorityId: Member + Parameter + RuntimeAppPublic + Default + Ord;
	// /// The overarching dispatch call type.
		/// A sudo-able call.
	type Call: Parameter + UnfilteredDispatchable<Origin=Self::Origin> + GetDispatchInfo;
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
}

pub type Data = Vec<u8>;
pub type Nonce = Vec<u8>;


decl_storage! {
	trait Store for Module<T: Config> as PrivateChannels {
		/// The current set of keys that may issue a heartbeat.
		Channels get(fn channels): map hasher(blake2_128_concat) T::AuthorityId => T::AccountId;
		EncryptedData get(fn encrypted_data): Vec<u8>;
		DecryptedData get(fn decrypted_data): Vec<u8>;
		EncryptionNonce get(fn encryption_nonce): Vec<u8>;
	}
	add_extra_genesis {
		config(channels): Vec<(T::AuthorityId, Vec<T::AccountId>)>;
		build(|config| Module::<T>::initialize_channels(&config.channels))
	}
}

decl_error! {
	pub enum Error for Module<T: Config> {
		InvalidNonce,
		// Error returned when not sure which ocw function to executed
		DecryptingError,
	}
}

decl_event! {
    pub enum Event<T>
	where
		AccountId = <T as system::Config>::AccountId,
	{
        /// Campaign is set
        DataSent(AccountId),
    }
}

decl_module! {
	/// A public part of the pallet.
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		#[weight = 0]
		// fn send_encrypted(origin, call: Box<<T as Config>::Call>, channel: T::AccountId) -> DispatchResult {
		fn send_encrypted(origin, data: Data, nonce: Nonce) -> DispatchResult {
			let sender = ensure_signed(origin.clone())?;
			// call.dispatch_bypass_filter(origin.clone());


			<EncryptedData>::put(data);
			<EncryptionNonce>::put(nonce);

			Self::deposit_event(Event::<T>::DataSent(sender));

			Ok(())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			// Only send messages if we are a potential validator.
			debug::info!("=============== OFF-CHAIN WORKER ============: {:?}", block_number);
			if sp_io::offchain::is_validator() {
				let result = Self::decrypt_and_sign(block_number);
				if let Err(e) = result {
				debug::error!("offchain_worker error: {:?}", e);
				}
			}
		}
	}
}

impl<T: Config> Module<T> {
	fn decrypt_and_sign(block_number: T::BlockNumber) -> Result<(), Error<T>> {
		let encrypted_data = EncryptedData::get();
		let nonce = <EncryptionNonce>::get();
		// let transformed_nonce = Self::get_nonce(nonce).ok_or(Error::<T>::InvalidNonce)?;

		let keys = Self::local_authority_keys();

		for key in keys {
			debug::info!("=================== KEYS ================= {:?}", key);
		}

		Ok(())

		// let decrypted_plaintext = box_::open(data.as_slice(), &transformed_nonce, &ourpk, &theirsk).unwrap();

	}

	fn local_authority_keys() -> impl Iterator<Item=T::AuthorityId> {
		let authorities = <Channels<T>>::iter();

		// All `PrivateChannels` public (+private) keys currently in the local keystore.
		let local_keys = T::AuthorityId::all();

		// local_keys.into_iter();

		// local_keys.sort();

		<Channels<T>>::iter()
			// .enumerate()
			.filter_map(move |(authority, _allowed_accounts)| {
				local_keys.binary_search(&authority)
					.ok()
					.map(|location| local_keys[location].clone())
			})
	}

	// fn get_nonce(nonce: Vec<u8>) -> Option<Nonce> {
	// 	Nonce::from_slice(nonce.as_slice())
	// }

	fn initialize_channels(channels: &[(T::AuthorityId, Vec<T::AccountId>)]) {
		if !channels.is_empty() {
			for (key, allowed_accounts) in channels.iter() {
				for allowed_account in allowed_accounts {
					<Channels<T>>::insert(key, allowed_account);
				}
			}
		}
	}
}
