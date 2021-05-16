#![cfg_attr(not(feature = "std"), no_std)]
use sp_std::prelude::*;
use sp_std::any::*;
use sp_application_crypto::RuntimeAppPublic;
use frame_system::{
	self as system,
	ensure_signed,
	ensure_none,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendUnsignedTransaction, SendSignedTransaction,
		SignedPayload, SigningTypes, Signer, SubmitTransaction,
	},
	EventRecord
};
use frame_support::{
	debug, Parameter,
	dispatch::DispatchResultWithPostInfo, decl_module, decl_storage, decl_event, decl_error,
	traits::{Get, UnfilteredDispatchable},
	weights::{GetDispatchInfo, Pays},
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain::{rpc, Duration, storage::StorageValueRef},
	traits::{Member, Zero, Hash},
	transaction_validity::{
		InvalidTransaction, ValidTransaction, TransactionValidity, TransactionSource,
		TransactionPriority,
	},
};
use codec::{Encode, Decode, HasCompact};
use sp_std::{vec::Vec, str, fmt};
use sp_io::hashing::{twox_128, blake2_256, blake2_128};

use serde_json::{Value};

pub const RPC_REQUEST_URL: &str = "http://localhost:9933";
pub const TIMEOUT_PERIOD: u64 = 3_000;
pub const JSONRPC: &str = "2.0";

const MODULE: &[u8] = b"System";
const EVENT_TOPIC_STORAGE: &[u8] = b"EventTopics";
const EVENT_STORAGE: &[u8] = b"Events";
const EVENT_TOPIC_NAME: &[u8] = b"encrypted-extrinsic-sent";
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
		use sp_application_crypto::{app_crypto, ed25519};
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
		Channels get(fn channels): double_map hasher(blake2_128_concat) T::AuthorityId, hasher(blake2_128_concat) T::AccountId => bool;
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
		InvalidSender,
	}
}

decl_event! {
    pub enum Event<T>
	where
		AccountId = <T as system::Config>::AccountId,
		AuthorityId = <T as Config>::AuthorityId,

	{
        EncryptedExtrinsicSent(AccountId, AuthorityId, Data, Nonce),
    }
}

decl_module! {
	/// A public part of the pallet.
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		#[weight = (0, Pays::No)]
		fn send_encrypted_extrinsic(origin, channel: T::AuthorityId, extrinsic: Data, nonce: Nonce) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin.clone())?;
			Self::sender_belongs_to_channel(&sender, &channel)?;

			let topic = T::Hashing::hash(EVENT_TOPIC_NAME);
			let event = <T as Config>::Event::from(RawEvent::EncryptedExtrinsicSent(sender, channel, extrinsic, nonce));

			<frame_system::Pallet<T>>::deposit_event_indexed(&[topic], event.into());

			Ok(().into())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			if sp_io::offchain::is_validator() {
				let finalized_head_response = Self::rpc_fetch_finalized_head();

				match finalized_head_response {
					Ok(response) => {
						if response.result.is_some() {
							debug::info!("Rpc call result: {:?}", response.result);
							let block_hash = response.result.unwrap();
							let block_hash_str = block_hash.as_str().unwrap();
							let events_topics_response = Self::rpc_fetch_block_events_topics(block_hash_str);

							match events_topics_response {
								Ok(response) => {
									if response.result.is_some() {
										let events_topics_result = response.result.unwrap();

										if !events_topics_result.is_null() {
											debug::info!("Rpc call result: {:?}", events_topics_result);
											let events_response = Self::rpc_fetch_block_events(block_hash_str);

											match events_response {
												Ok(response) => {
													if response.result.is_some() {
														let events_result = response.result.unwrap();

														if !events_result.is_null() {
															Self::get_events(&events_topics_result, &events_result);
														}
													}
												},
												Err(e) => debug::error!("Offchain_worker error state_getStorageAt: {:?}", e)
											}
										}
									} else {
										let error = response.error.unwrap();
										debug::error!(
											"Rpc call error state_getStorageAt: code: {:?}, message: {:?}",
											error.code,
											error.message
										);
									}
								},
								Err(e) => debug::error!("Offchain_worker error state_getStorageAt: {:?}", e)
							}
						} else {
							let error = response.error.unwrap();
							debug::error!(
								"Rpc call error chain_getFinalizedHead: code: {:?}, message: {:?}",
								error.code,
								error.message
							);
						}
					},
					Err(e) => debug::error!("Offchain_worker error chain_getFinalizedHead: {:?}", e)
				}
			}
		}
	}
}

impl<T: Config> Module<T> {
	fn type_of<Z>(_: Z) -> &'static str {
		type_name::<Z>()
	}

	fn rpc_fetch_finalized_head() -> Result<rpc::Response, rpc::Error> {
		let request = rpc::Request::new();
		let response = request.send()?;
		Ok(response)
	}

	fn rpc_fetch_block_events_topics(block_hash: &str) -> Result<rpc::Response, rpc::Error> {
		let module_key = twox_128(MODULE);
		let event_topic_storage_key = twox_128(EVENT_TOPIC_STORAGE);
		let event_topic_name = blake2_256(EVENT_TOPIC_NAME);
		let event_topic_hash = blake2_128(&event_topic_name);
		let private_channels_events_key_str = &[&module_key[..], &event_topic_storage_key[..], &event_topic_hash[..], &event_topic_name[..]].concat();
		let private_channels_events_key_hex = hex::encode(&private_channels_events_key_str);
		let private_channels_events_key_slc = &[b"0x", private_channels_events_key_hex.as_bytes()].concat();
		let private_channels_events_key = str::from_utf8(private_channels_events_key_slc).unwrap();

		let request = rpc::Request::new()
			.method("state_getStorageAt")
			.params(vec![private_channels_events_key, block_hash]);

		let response = request.send()?;
		Ok(response)
	}

	fn rpc_fetch_block_events(block_hash: &str) -> Result<rpc::Response, rpc::Error> {
		let module_key = twox_128(MODULE);
		let events_storage_key = twox_128(EVENT_STORAGE);
		let events_key_str = &[&module_key[..], &events_storage_key[..]].concat();
		let events_key_hex = hex::encode(&events_key_str);
		let events_key_slc = &[b"0x", events_key_hex.as_bytes()].concat();
		let events_key = str::from_utf8(events_key_slc).unwrap();

		let request = rpc::Request::new()
			.method("state_getStorageAt")
			.params(vec![events_key, block_hash]);

		let response = request.send()?;
		Ok(response)
	}

	fn get_events(event_topics: &Value, events: &Value) {
		let event_topics_str = event_topics.as_str().unwrap();
		let event_topics_vec = hex::decode(&event_topics_str[2..]).ok().unwrap();

		let topics = <Vec<(u32, u32)>>::decode(&mut &*event_topics_vec).ok();

		debug::info!("============= TOPICS ============== {:?}", topics);

		let events_str = events.as_str().unwrap();
		let events_vec = hex::decode(&events_str[2..]).ok().unwrap();

		let events = <Vec<EventRecord<<T as frame_system::Config>::Event, <T as frame_system::Config>::Hash>>>::decode(&mut &*events_vec).ok();

		debug::info!("============= Events ============== {:?}", events.unwrap());

		let events = Self::rpc_fetch_block_evetns(block_hash)

		for topic in topics.unwrap().iter() {
			debug::info!("============= TOPIC ============== {:?}", topic);
			let (block_number, index) = topic;
			Self::get_event_by_index(*index)
		}
	}

	// fn get_event_by_index(index: u32) {
	// 	let i = index as usize;
	// 	let events = SystemPallet::<T>::events();
	// 	debug::info!("============= EVENT ============== {:?}", events[i]);
	// }

	// fn get_events_data_from_owned_channels() -> Vec<EncryptedExtrinsicData<T>> {
	// fn get_events_data_from_owned_channels() {
	// 	let events_records = frame_system::Pallet::<T>::events();
	// 	let owned_channel_keys = T::AuthorityId::all();
	// 	// let encrypted_extrinsic_data = Vec::new();

	// 	events_records.iter().for_each(|event_record| {
	// 		// debug::info!("================= TYPE ================ {:?}", Self::type_of(*&event_record.event));
	// 		match &event_record.event {
	// 			// Event(e) => debug::info!("================= EVENT ================ {:?}", Self::type_of(&event_record.event))
	// 			T::Event(e) => debug::info!("================= EVENT ================ {:?}", Self::type_of(e))
	// 		};
	// 	});
	// 	// Vec<EventRecord<T::Event, T::Hash>>



	// 	// let mut channels = Vec::new();

	// 	// <Channels<T>>::iter().for_each(|(authority, _allowed_accounts, _bool)| {
	// 	// 	channels.push((authority))
	// 	// });

	// 	// debug::info!("================ CHANNELS 1 ==============: {:?}", channels);

	// 	// // channels.filter(|channel| {
	// 	// // 	owned_channel_keys.binary_search(&channel).is_ok()
	// 	// // }).collect()
	// 	// owned_channel_keys
	// }

	fn sender_belongs_to_channel(sender: &T::AccountId, channel: &T::AuthorityId) -> Result<(), Error<T>> {
		if <Channels<T>>::contains_key(channel, sender) {
			Ok(())
		} else { Err(Error::<T>::InvalidSender) }
	}

	// fn decrypt_and_sign(block_number: T::BlockNumber) -> Result<(), Error<T>> {
	// 	let encrypted_data = EncryptedData::get();
	// 	let nonce = <EncryptionNonce>::get();
	// 	// let transformed_nonce = Self::get_nonce(nonce).ok_or(Error::<T>::InvalidNonce)?;

	// 	let keys = Self::local_authority_keys();
	// 	// debug::info!("=================== ENTRA ================= {:?}", keys.count());
	// 	// debug::info!("=================== ENTRA ================= {:?}", keys);

	// 	keys.for_each( |key| {
	// 		debug::info!("=================== KEYS ================= {:?}", key);
	// 	});

	// 	Ok(())

	// 	// let decrypted_plaintext = box_::open(data.as_slice(), &transformed_nonce, &ourpk, &theirsk).unwrap();

	// }

	// fn local_authority_keys() -> impl Iterator<Item=T::AuthorityId> {
	// 	let authorities = <Channels<T>>::iter();

	// 	// All `PrivateChannels` public (+private) keys currently in the local keystore.
	// 	let local_keys = T::AuthorityId::all();

	// 	debug::info!("=================== LOCAL KEYS ================= {:?}", local_keys);

	// 	// local_keys.into_iter();

	// 	// local_keys.sort();

	// 	let local_keys_2 = local_keys.clone();

	// 	// <Channels<T>>::iter()
	// 	// 	.filter_map(move |(authority, _allowed_accounts, _bool)| {
	// 	// 		if local_keys.binary_search(&authority).ok() {

	// 	// 		}
	// 	// 		debug::info!("=================== INDEX ================= {:?}", index);
	// 	// 		// local_keys[index]
	// 	// 			// .map(|location| local_keys[location].clone())
	// 	// 	});

	// 	<Channels<T>>::iter()
	// 		// .enumerate()
	// 		.filter_map(move |(authority, _allowed_accounts, _bool)| {
	// 			local_keys_2.binary_search(&authority).ok().map(|location| local_keys_2[location].clone())
	// 		})
	// }

	// fn get_nonce(nonce: Vec<u8>) -> Option<Nonce> {
	// 	Nonce::from_slice(nonce.as_slice())
	// }

	fn initialize_channels(channels: &[(T::AuthorityId, Vec<T::AccountId>)]) {
		if !channels.is_empty() {
			for (key, allowed_accounts) in channels.iter() {
				for allowed_account in allowed_accounts {
					<Channels<T>>::insert(key, allowed_account, true);
				}
			}
		}
	}
}
