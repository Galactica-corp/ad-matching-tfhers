use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);
    // On the server side:
    set_server_key(server_keys);

    let user_profile = 0x00ffu32;
    // Encrypting the input data using the (private) client_key
    let encrypted_user_profile = FheUint32::try_encrypt(user_profile, &client_key)?;

    let target_profile = 0xaaaau32;

    let start_time = std::time::Instant::now();
    let encrypted_distance = fhe_hamming_distance(&encrypted_user_profile, target_profile)?;
    let elapsed = start_time.elapsed();
    println!("Hamming Distance: {:?}", elapsed);

    let start_time = std::time::Instant::now();
    let encrypted_score = fhe_overlap_score(&encrypted_user_profile, target_profile)?;
    let elapsed = start_time.elapsed();
    println!("Overlap Score: {:?}", elapsed);

    // Decrypting on the client side:
    let clear_res: u32 = encrypted_distance.decrypt(&client_key);
    println!("Distance: {clear_res}");

    let clear_score: u32 = encrypted_score.decrypt(&client_key);
    println!("Score: {clear_score}");

    println!("Done!");
    Ok(())
}

/**
 * Calculate the binary hamming distance between the user profile and the target profile
 */
fn fhe_hamming_distance(
    encrypted_user_profile: &FheUint32,
    target_profile: u32,
) -> Result<FheUint32, Box<dyn std::error::Error>> {
    // Binary XOR
    let encrypted_xor = encrypted_user_profile ^ target_profile;

    // Count set bits to get the distance between both
    let encrypted_distance = encrypted_xor.count_ones();

    return Ok(encrypted_distance);
}

/**
 * Calculate the the score of how well the user profile matches the target profile. If it is a perfect match, the score is the amount of bits set in the target profile.
 */
fn fhe_overlap_score(
    encrypted_user_profile: &FheUint32,
    target_profile: u32,
) -> Result<FheUint32, Box<dyn std::error::Error>> {
    // Binary AND
    let encrypted_and = encrypted_user_profile & target_profile;

    // Count set bits to get the distance between both
    let encrypted_score = encrypted_and.count_ones();

    return Ok(encrypted_score);
}
