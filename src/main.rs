use alloy_primitives::Address;
// use alloy_signer::{Signer};
use k256::{ecdsa::SigningKey, sha2::Sha512, PublicKey};
use tiny_keccak::{Keccak, Hasher};
use rand::rngs::OsRng;
use anyhow::{Error, Ok, Result};
// use bip39::{Mnemonic, MnemonicType, Language, Seed};
use hmac::{Hmac, Mac};


#[derive(Debug)]
pub struct Wallet {
    private_key: SigningKey,
    public_key: PublicKey,
    address: Address,
    // mnemonic: Option<String>,
}

impl Wallet {
    pub fn new_random_wallet_generation() -> Result<Self> {
        // generating random wallet
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = private_key.verifying_key().to_encoded_point(false);

        // generating Eth address (keccak256(public_key)[12:])
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(&public_key.as_bytes()[1..]); // skip the 0x04 prefix please
        hasher.finalize(&mut hash);
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        let address = Address::from_slice(&address_bytes);

        let public_key = (*private_key.verifying_key()).into();

        Ok(Self {
            private_key,
            public_key,
            address,
    
        })
    }

    pub fn get_account_from_private_key(private_key_hex: &str) -> Result<Self> {
        // Remove "0x" prefix if present
        let private_key_hex = private_key_hex.trim_start_matches("0x");
        
        // Convert hex string to bytes
        let private_key_bytes = hex::decode(private_key_hex)
            .map_err(|e| Error::msg(format!("Invalid private key hex format: {}", e)))?;
            
        // Create SigningKey from bytes
        let private_key = SigningKey::from_bytes(private_key_bytes.as_slice().into())
            .map_err(|e| Error::msg(format!("Invalid private key: {}", e)))?;
            
        // Get public key
        let public_key = private_key.verifying_key().to_encoded_point(false);
        
        // Generate Ethereum address
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(&public_key.as_bytes()[1..]); // Skip the 0x04 prefix
        hasher.finalize(&mut hash);
        
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..32]);
        let address = Address::from_slice(&address_bytes);
        
        let public_key = (*private_key.verifying_key()).into();
        
        Ok(Self {
            private_key,
            public_key,
            address,
        })
    }
    


    pub fn get_address(&self) -> String {
        format!("{:#x}", self.address)
    }

    // pub fn get_public_key(&self) -> String {
    //     format!("{:#x}", self.public_key)
    // }

    pub fn export_private_key(&self) -> String {
        // Convert private key to bytes and format as hex string
        // Skip "0x" prefix as many wallets expect raw hex
        let private_key_bytes = self.private_key.to_bytes();
        hex::encode(private_key_bytes)
    }

}

fn main() -> Result<()> {
    let wallet = Wallet::new_random_wallet_generation()?;

    println!("{:?}", wallet);

    println!("Wallet Address: {}\n\n", wallet.get_address());

    let wallet_private_key = Wallet::get_account_from_private_key(&wallet.export_private_key().as_str());   

    // println!("Private Key: {:#x}", wallet_private_key.unwrap().export_private_key());

    
   
    Ok(())

    
}