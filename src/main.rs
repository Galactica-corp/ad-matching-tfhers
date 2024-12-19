use tfhe::integer::U256;
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint256, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);
    // On the server side:
    set_server_key(server_keys);

    let user_profile = U256::from((0x00ffu128, 0x00ffu128));
    // Encrypting the input data using the (private) client_key
    let encrypted_user_profile = FheUint256::try_encrypt(user_profile, &client_key)?;

    let target_profile = U256::from((0xaaaau128, 0xaaaau128));

    let start_time = std::time::Instant::now();
    let encrypted_distance = fhe_hamming_distance(&encrypted_user_profile, target_profile)?;
    let elapsed = start_time.elapsed();
    println!("Hamming Distance: {:?}", elapsed);

    let start_time = std::time::Instant::now();
    let encrypted_score = fhe_overlap_score(&encrypted_user_profile, target_profile)?;
    let elapsed = start_time.elapsed();
    println!("Overlap Score: {:?}", elapsed);

    // Decrypting on the client side:
    let clear_res: u128 = encrypted_distance.decrypt(&client_key);
    println!("Distance: {clear_res}");

    let clear_score: u128 = encrypted_score.decrypt(&client_key);
    println!("Score: {clear_score}");

    println!("Done!");
    Ok(())
}

/**
 * Calculate the binary hamming distance between the user profile and the target profile
 */
fn fhe_hamming_distance(
    encrypted_user_profile: &FheUint256,
    target_profile: U256,
) -> Result<FheUint32, Box<dyn std::error::Error>> {
    // Binary XOR
    let start_time = std::time::Instant::now();
    let encrypted_xor = encrypted_user_profile ^ target_profile;
    let elapsed = start_time.elapsed();
    println!("XOR operation: {:?}", elapsed);

    // Count set bits to get the distance between both
    let start_time = std::time::Instant::now();
    let encrypted_distance = encrypted_xor.count_ones();
    let elapsed = start_time.elapsed();
    println!("Count ones operation: {:?}", elapsed);

    return Ok(encrypted_distance);
}

/**
 * Calculate the the score of how well the user profile matches the target profile. If it is a perfect match, the score is the amount of bits set in the target profile.
 */
fn fhe_overlap_score(
    encrypted_user_profile: &FheUint256,
    target_profile: U256,
) -> Result<FheUint32, Box<dyn std::error::Error>> {
    let start_time = std::time::Instant::now();
    // Binary AND
    let encrypted_and = encrypted_user_profile & target_profile;
    let elapsed = start_time.elapsed();
    println!("AND operation: {:?}", elapsed);

    // Count set bits to get the distance between both
    let start_time = std::time::Instant::now();
    let encrypted_score = encrypted_and.count_ones();
    let elapsed = start_time.elapsed();
    println!("Count ones operation: {:?}", elapsed);

    return Ok(encrypted_score);
}

// /**
//  * Simple benchmark to compare performance with the benchmarks made by Zama
//  */
// fn fhe_benchmark(client_key: &ClientKey) -> Result<(), Box<dyn std::error::Error>> {
//     // Binary AND
//     let secret = 0x123456u128;
//     let encrypted = FheUint128::try_encrypt(secret, client_key)?;
//     let scalar = 0xabcdefu128;

//     let start_time = std::time::Instant::now();
//     let result = &encrypted & scalar;
//     let elapsed = start_time.elapsed();
//     println!("& scalar operation: {:?}", elapsed);

//     let verify: u128 = result.decrypt(client_key);
//     assert_eq!(verify, secret & scalar);

//     return Ok(());
// }
