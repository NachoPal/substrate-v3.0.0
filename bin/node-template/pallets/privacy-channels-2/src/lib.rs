#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;
use rust_sodium::crypto::box_::{Nonce};

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

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		InvalidNonce,
	}

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
			let (ourpk, oursk) = box_::gen_keypair();
			let (theirpk, theirsk) = box_::gen_keypair();

			let transformed_nonce = Pallet::<T>::get_nonce(nonce).ok_or(Error::<T>::InvalidNonce)?;
			let decrypted_plaintext = box_::open(data.as_slice(), &transformed_nonce, &ourpk, &theirsk).unwrap();

			<EncryptedData<T>>::put(decrypted_plaintext);

            // Self::deposit_event(Event::AccountAllowed(new_account));

            Ok(().into())
        }
	}
}

impl<T:Config> Pallet<T> {
	fn get_nonce(nonce: Vec<u8>) -> Option<Nonce> {
		Nonce::from_slice(nonce.as_slice());
	}
}
