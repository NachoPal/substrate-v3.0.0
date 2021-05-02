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
	}
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
	offchain::{http, Duration, storage::StorageValueRef},
	traits::{Member, Zero, Hash},
	transaction_validity::{
		InvalidTransaction, ValidTransaction, TransactionValidity, TransactionSource,
		TransactionPriority,
	},
};
use codec::{Encode, Decode};
use sp_std::{vec::Vec, str, fmt};
use sp_io::hashing::{twox_128, blake2_256, blake2_128};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
// use sodiumoxide::crypto::box_::{Nonce};

pub const RPC_REQUEST_URL: &str = "http://localhost:9933";
pub const TIMEOUT_PERIOD: u64 = 3_000; // in milli-seconds
pub const JSON_STRING: &str = "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"chain_getFinalizedHead\",\"params\":[]}";
pub const JSONRPC: &str = "2.0";

const MODULE: &[u8] = b"System";
const EVENT_TOPIC_STORAGE: &[u8] = b"EventTopics";
const EVENT_TOPIC_NAME: &[u8] = b"encrypted-extrinsic-sent";
/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"priv");

#[derive(Deserialize, Encode, Decode, Default, RuntimeDebug)]
struct RpcResponse {
	#[serde(deserialize_with = "de_string_to_bytes")]
	jsonrpc: Vec<u8>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	result: Vec<u8>,
	id: u32
}

struct RpcRequest<'a> {
	jsonrpc: &'a str,
	id: u32,
	method: &'a str,
	params: Vec<&'a str>,
	timeout: u64,
	url: &'a str
}

// struct RpcRequest {
// 	jsonrpc: &str,
// 	id: u32,
// 	method: &str,
// 	params: Vec<&str>,
// 	timeout: u64,
// 	url: &str
// }

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(de)?;
	Ok(s.as_bytes().to_vec())
}

// pub fn se_bytes_to_string<S>(se: S) -> Result<&str, S::Error>
// where
// 	S: Serializer,
// {
// 	let d: &str = Serialize::serialize(se)?;
// 	// str::from_utf8(se).unwrap()
// 	Ok(d)
// }

// pub type RpcResponse = RpcResultStruct;

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

		// pub struct EncryptedExtrinsicData<T> {
		// 	pub seder: T::AccountId,
		// 	pub channel: T::AuthorityId,
		// 	pub nonce: Nonce,
		// }

		fn deposit_event() = default;

		#[weight = (0, Pays::No)]
		fn send_encrypted_extrinsic(origin, channel: T::AuthorityId, extrinsic: Data, nonce: Nonce) -> DispatchResultWithPostInfo {
			let sender = ensure_signed(origin.clone())?;
			Self::sender_belongs_to_channel(&sender, &channel)?;
			// call.dispatch_bypass_filter(origin.clone());

			// let module_name = b"PrivateChannels";

			// let module_hash = twox_128(&module_name[..]);

			// <EncryptedData>::put(data);
			// <EncryptionNonce>::put(nonce);

			let topic = T::Hashing::hash(EVENT_TOPIC_NAME);

			let event = <T as Config>::Event::from(RawEvent::EncryptedExtrinsicSent(sender, channel, extrinsic, nonce));

			<frame_system::Pallet<T>>::deposit_event_indexed(&[topic], event.into());

			Ok(().into())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			if sp_io::offchain::is_validator() {
				let finalized_head_result = Self::fetch_finalized_head();

				if let Err(e) = finalized_head_result {
					debug::error!("offchain_worker error: {:?}", e);
				} else {
					let finalized_block_hash_vec = finalized_head_result.ok().unwrap().result;
					let finalized_block_hash = str::from_utf8(&finalized_block_hash_vec[..]).unwrap();
					debug::info!("=================== finalized_block_hash ================== {:?}", finalized_block_hash);
					let finalized_block_events_result = Self::fetch_finalized_block_events(&finalized_block_hash);

					if let Err(e) = finalized_block_events_result {
						debug::error!("offchain_worker error: {:?}", e);
					} else {
						let finalized_block_events = finalized_block_events_result.ok().unwrap().result;
						debug::info!("=================== finalized_events ================== {:?}", finalized_block_events);
					}
				}

				// let param1 = b"hola".to_vec();
				// let param2 = b"mundo".to_vec();
				// let params = vec![param1, param2];
				// let method = b"chain_getFinalizedHead".to_vec();
				// let jsonrpc = b"2.0".to_vec();
				// let id = 1;

				// let param1 = str::from_utf8(b"hola").unwrap();
				// let param2 = str::from_utf8(b"mundo").unwrap();
				// let params = vec![param1, param2];
				// let method = str::from_utf8(b"chain_getFinalizedHead").unwrap();
				// let jsonrpc = str::from_utf8(b"2.0").unwrap();
				// let id = 1;

				// let param1 = "hola";
				// let param2 = b"mundo";
				// let params = vec![param1, param2];
				// let method = b"chain_getFinalizedHead";
				// let jsonrpc = b"2.0";
				// let id = 1;

				// jsonrpc: Vec<u8>, id: u32, method: Vec<u8>, params: Vec<Vec<u8>>

				// Self::rpc_call(jsonrpc, id, method, params);



				// debug::info!("=================== RESPONSE ================== {:?}", str::from_utf8(&finalized_block_hash).unwrap());


				// 	.map_err(|_| http::Error::IoError)?;

				// let response = pending.try_wait(deadline)
				// 	.map_err(|_| http::Error::DeadlineReached)??;

				// let owned_channels = Self::get_events_data_from_owned_channels();
				// let owned_channels = Self::get_events_data_from_owned_channels();

				// debug::info!("================ CHANNELS ==============: {:?}", owned_channels);
				// Self::get_events_for_owned_channels(&owned_channels);
				// let result = Self::decrypt_and_sign(block_number);
				// if let Err(e) = result {
				// 	debug::error!("offchain_worker error: {:?}", e);
				// }
				// Self::search_for_send_extrinsic_events(block_number);
			}
		}
	}
}

//event: Event::private_channels(RawEvent::EncryptedExtrinsicSent

impl<T: Config> Module<T> {
	fn type_of<Z>(_: Z) -> &'static str {
		type_name::<Z>()
	}

	fn fetch_finalized_head() -> Result<RpcResponse, http::Error> {
		let rpc_request = RpcRequest {
			jsonrpc: JSONRPC,
			id: 1,
			method: "chain_getFinalizedHead",
			params: Vec::new(),
			timeout: TIMEOUT_PERIOD,
			url: RPC_REQUEST_URL
		};

		let rpc_response = Self::rpc_call(rpc_request)?;
		Ok(rpc_response)
	}

	fn fetch_finalized_block_events(block_hash: &str) -> Result<RpcResponse, http::Error> {
		let module_key = twox_128(MODULE);
		let event_topic_storage_key = twox_128(EVENT_TOPIC_STORAGE);
		let event_topic_name = blake2_256(EVENT_TOPIC_NAME);
		let event_topic_hash = blake2_128(&event_topic_name);
		let private_channels_events_key_str = &[&module_key[..], &event_topic_storage_key[..], &event_topic_hash[..], &event_topic_name[..]].concat();
		let private_channels_events_key_hex = hex::encode(&private_channels_events_key_str);
		let private_channels_events_key_slc = &[b"0x", private_channels_events_key_hex.as_bytes()].concat();
		let private_channels_events_key = str::from_utf8(private_channels_events_key_slc).unwrap();

		let rpc_request = RpcRequest {
			jsonrpc: "2.0",
			id: 1,
			method: "state_getStorageAt",
			params: vec![private_channels_events_key, block_hash],
			timeout: TIMEOUT_PERIOD,
			url: RPC_REQUEST_URL
		};

		let rpc_response = Self::rpc_call(rpc_request)?;
		Ok(rpc_response)
	}

	fn rpc_call(request: RpcRequest) -> Result<RpcResponse, http::Error> {
		let request_body = json!({
			"jsonrpc": request.jsonrpc,
			"id": request.id,
			"method": request.method,
			"params": request.params
		});

		debug::info!("========================= BODY CONSTRUCT ==================== {:?}", serde_json::to_string(&request_body).unwrap());

		let mut body: Vec<&[u8]> = Vec::new();
		// let request_body_vec: Vec<u8> = serde_json::to_vec(&request_body).unwrap();
		let request_body_slice: &[u8] = &(serde_json::to_vec(&request_body).unwrap())[..];
		// let request_body_slice: &[u8] = &v[..];
		body.push(request_body_slice);

		let post_request = http::Request::post(request.url, body);

		let timeout = sp_io::offchain::timestamp().add(Duration::from_millis(TIMEOUT_PERIOD));

		let pending = post_request
			.add_header("Content-Type", "application/json;charset=utf-8")
			.deadline(timeout)
			.send().map_err(|_| http::Error::IoError)?;

		let response = pending.try_wait(timeout)
			.map_err(|_| http::Error::DeadlineReached)??;

		if response.code != 200 {
			debug::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown);
		}

		let response_body_bytes = response.body().collect::<Vec<u8>>();

		let response_body_str = str::from_utf8(&response_body_bytes).map_err(|_| http::Error::Unknown)?;

		debug::info!("=================== RESPONSE RAW ================== {:?}", response_body_str);


		let rpc_response: RpcResponse = serde_json::from_str(&response_body_str).map_err(|_| http::Error::Unknown)?;

		Ok(rpc_response)
	}

	// fn fetch_finalized_block_hash() -> Result<Vec<u8>, http::Error> {
	// 	let mut body: Vec<&'static [u8]> = Vec::new();
	// 	body.push(FETCH_FINALIZED_BLOCK_HASH_BODY);

	// 	let request = http::Request::post(HTTP_LOCAL_RPC_REQUEST, body);

	// 	let timeout = sp_io::offchain::timestamp().add(Duration::from_millis(FETCH_TIMEOUT_PERIOD));

	// 	let pending = request
	// 		.add_header("Content-Type", "application/json;charset=utf-8")
	// 		.deadline(timeout)
	// 		.send().map_err(|_| http::Error::IoError)?;

	// 	let response = pending.try_wait(timeout)
	// 		.map_err(|_| http::Error::DeadlineReached)??;
	// 	// Let's check the status code before we proceed to reading the response.
	// 	if response.code != 200 {
	// 		debug::warn!("Unexpected status code: {}", response.code);
	// 		return Err(http::Error::Unknown);
	// 	}

	// 	let response_body_bytes = response.body().collect::<Vec<u8>>();

	// 	let response_body_str = str::from_utf8(&response_body_bytes).map_err(|_| http::Error::Unknown)?;

	// 	debug::info!("=================== RESPONSE RAW ================== {:?}", response_body_str);


	// 	let rpc_response: RpcResponse = serde_json::from_str(&response_body_str).map_err(|_| http::Error::Unknown)?;

	// 	Ok(rpc_response.result)
	// }

	// fn fetch_finalized_block_events(block_hash: &Vec<u8>) -> Result<(), http::Error> {
	// 	debug::info!("=================== ENTRA ================== ");
	// 	// let mut body: Vec<&'static [u8]> = Vec::new();
	// 	// body.push(FETCH_FINALIZED_BLOCK_HASH_BODY);

	// 	// let request = http::Request::post(HTTP_LOCAL_RPC_REQUEST, body);

	// 	// let timeout = sp_io::offchain::timestamp().add(Duration::from_millis(FETCH_TIMEOUT_PERIOD));

	// 	// let pending = request
	// 	// 	.add_header("Content-Type", HTTP_HEADER_CONTENT_TYPE)
	// 	// 	.deadline(timeout)
	// 	// 	.send().map_err(|_| http::Error::IoError)?;

	// 	// let response = pending.try_wait(timeout)
	// 	// 	.map_err(|_| http::Error::DeadlineReached)??;
	// 	// // Let's check the status code before we proceed to reading the response.
	// 	// if response.code != 200 {
	// 	// 	debug::warn!("Unexpected status code: {}", response.code);
	// 	// 	return Err(http::Error::Unknown);
	// 	// }

	// 	// let response_body_bytes = response.body().collect::<Vec<u8>>();

	// 	// let response_body_str = str::from_utf8(&response_body_bytes).map_err(|_| http::Error::Unknown)?;

	// 	// debug::info!("=================== RESPONSE RAW ================== {:?}", response_body_str);


	// 	// let rpc_response: RpcResponse = serde_json::from_str(&response_body_str).map_err(|_| http::Error::Unknown)?;

	// 	// Ok(rpc_response.result)

	// 	// storage::hashed::get_or(&blake2_256, &who.to_keyed_vec(NONCE_OF), 0)
	// 	let module_key = twox_128(MODULE);
	// 	let event_topic_storage_key = twox_128(EVENT_TOPIC_STORAGE);
	// 	// let event_topic_storage_key = twox_128(EVENT_STORAGE);

	// 	let event_topic_name = blake2_256(EVENT_TOPIC_NAME);
	// 	let event_topic_hash = blake2_128(&event_topic_name);

	// 	let private_channels_events_key = &[&module_key[..], &event_topic_storage_key[..], &event_topic_hash[..], &event_topic_name[..]].concat();

	// 	// let a = str::from_utf8(&private_channels_events_key).unwrap();

	// 	debug::info!("=================== EVENT TOPIC KEY ================== {:?}",hex::encode(&private_channels_events_key));

	// 	// let params = format!("params\":[{}]", str::from_utf8(&block_hash).unwrap());

	// 	// let a = FETCH_FINALIZED_BLOCK_EVENTS_BODY.extend_from_slice(params);
	// 	// debug::info!("=================== URL ================== {:?}", &params);

	// 	// let _events_key = &[&module_key[..], &event_topic_storage_key[..]].concat();

	// 	Ok(())
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
