#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(any(
    feature = "u32_backend",
    feature = "u64_backend",
    feature = "fiat_u32_backend",
    feature = "fiat_u64_backend"
)))]

use sp_std::prelude::*;
use crypto_box::{Box, PublicKey, SecretKey, aead::Aead};
use salsa20::{XSalsa20, cipher::{NewStreamCipher}};
use generic_array::{GenericArray};

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use frame_support::{dispatch::DispatchResultWithPostInfo, pallet_prelude::*};
	use frame_system::pallet_prelude::*;
	use super::*;
	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		// type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	pub type EncryptedData<T: Config> =  StorageValue<_, Vec<u8>>;

	// #[pallet::event]
	// #[pallet::metadata(T::AccountId = "AccountId")]
	// #[pallet::generate_deposit(pub(super) fn deposit_event)]
	// pub enum Event<T: Config> {
	// 	// Data sent
    //     EncryptedDataSent()
	// }

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::call]
	impl<T:Config> Pallet<T> {
		/// Add a new account to the allow-list.
        /// Can only be called by the root.
        #[pallet::weight(0)]
        pub fn send_data(origin: OriginFor<T>, data: Vec<u8>, nonce: Vec<u8>) -> DispatchResultWithPostInfo {
            // ensure_root(origin)?;
			// Alice is validator 1

			let valid_nonce = Pallet::<T>::get_nonce(nonce);

			let alice_public_key = PublicKey::from([
				0x1a,0x0e, 0x2b, 0xf1, 0xe0, 0x19, 0x5a, 0x1f,
				0x53, 0x96, 0xc5, 0xfd, 0x20, 0x9a, 0x62, 0x0a,
				0x48, 0xfe, 0x90, 0xf6, 0xf3, 0x36, 0xd8, 0x9c,
				0x89, 0x40, 0x5a, 0x01, 0x83, 0xa8, 0x57, 0xa3
			]);

			let bob_secret_key = SecretKey::from([
				0xb5, 0x81, 0xfb, 0x5a, 0xe1, 0x82, 0xa1, 0x6f,
				0x60, 0x3f, 0x39, 0x27, 0xd, 0x4e, 0x3b, 0x95,
				0xbc, 0x0, 0x83, 0x10, 0xb7, 0x27, 0xa1, 0x1d,
				0xd4, 0xe7, 0x84, 0xa0, 0x4, 0x4d, 0x46, 0x1b
			]);


			let bob_box = Box::new(&alice_public_key, &bob_secret_key);

			let decrypted_plaintext = bob_box.decrypt(&valid_nonce, data.as_slice()).unwrap();

			<EncryptedData<T>>::put(decrypted_plaintext);

            // Self::deposit_event(Event::AccountAllowed(new_account));

            Ok(().into())
        }
	}
}

impl<T:Config> Pallet<T> {
	fn get_nonce(nonce: Vec<u8>) -> GenericArray<u8, <XSalsa20 as NewStreamCipher>::NonceSize> {
		// let nonce_clone = nonce.clone();
		let valid_nonce = GenericArray::<u8, <XSalsa20 as NewStreamCipher>::NonceSize>::from_slice(nonce.as_slice());
		*valid_nonce
	}
}
