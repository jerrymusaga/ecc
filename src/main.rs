use k256::{
    ecdsa::SigningKey,
    PublicKey,
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::{Sha256, Digest};
use hex;
use rand_core::OsRng;

fn generate_private_key() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

fn derive_public_key(private_key: &SigningKey) -> PublicKey {
    PublicKey::from(private_key.verifying_key())
}

fn generate_address(public_key: &PublicKey) -> String {
    // Convert public key to encoded point
    let encoded_point = public_key.to_encoded_point(false);
    
    // Hash public key
    let mut hasher = Sha256::new();
    hasher.update(encoded_point.as_bytes());
    let hash = hasher.finalize();
    
    // Take last 20 bytes as address
    let address = &hash[hash.len()-20..];
    format!("0x{}", hex::encode(address))
}

pub fn main() {
    // Generate private key
    let private_key = generate_private_key();
    println!("Private Key: {}", hex::encode(private_key.to_bytes()));
    
    // Derive public key
    let public_key = derive_public_key(&private_key);
    
    // Get public key bytes using to_encoded_point
    let public_key_bytes = public_key.to_encoded_point(false);
    println!("Public Key: {}", hex::encode(public_key_bytes.as_bytes()));
    
    // Generate address
    let address = generate_address(&public_key);
    println!("Address: {}", address);
}