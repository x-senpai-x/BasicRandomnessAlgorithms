//! Shamir's Secret Sharing Scheme demonstration.
//!
//! This example demonstrates how to use Shamir's secret sharing scheme to:
//! 1. Split a secret into n shares with threshold t
//! 2. Reconstruct the secret from any t shares

use crypto_field::FiniteField;
use crypto_shamir::{ShamirScheme, Share};
use rand::Rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parameters for Shamir secret sharing
    let threshold = 2; // Minimum number of shares needed to reconstruct
    let n_shares = 5; // Total number of shares to create
    let secret_value = 43; // The secret to share
    let modulus = 97; // A prime number for the finite field

    println!("=== Shamir Secret Sharing Demo ===\n");
    println!("Threshold (t): {}", threshold);
    println!("Total shares (n): {}", n_shares);
    println!("Secret: {}", secret_value);
    println!("Modulus: {}\n", modulus);

    // Create the secret as a finite field element
    let secret = FiniteField::new(secret_value, modulus)?;

    // Create a Shamir scheme
    let scheme = ShamirScheme::new(threshold, n_shares, modulus)?;

    // Generate shares
    println!("--- Step 1: Generating Shares ---");
    let shares = scheme.share(secret)?;

    println!("Generated {} shares:", shares.len());
    for (i, share) in shares.iter().enumerate() {
        println!(
            "  Share {}: (index={}, value={})",
            i + 1,
            share.index(),
            share.value()
        );
    }
    println!();

    // Demonstrate reconstruction with threshold shares
    println!(
        "--- Step 2: Reconstructing Secret from Random {} Shares ---",
        threshold
    );

    // Randomly select t shares
    let selected_indices = generate_unique_random_indices(n_shares as u64, threshold);
    println!("Randomly selected share indices: {:?}", selected_indices);

    let mut t_shares: Vec<Share> = Vec::new();
    for &idx in &selected_indices {
        t_shares.push(shares[idx as usize].clone());
    }

    println!("Selected shares:");
    for share in &t_shares {
        println!(
            "  Share: (index={}, value={})",
            share.index(),
            share.value()
        );
    }
    println!();

    // Reconstruct the secret
    let reconstructed = scheme.reconstruct(&t_shares)?;

    println!("--- Result ---");
    println!("Original secret: {}", secret.value());
    println!("Reconstructed secret: {}", reconstructed.value());

    if secret.value() == reconstructed.value() {
        println!("\n✓ Success! Secret reconstructed correctly.");
    } else {
        println!("\n✗ Error: Reconstruction failed!");
    }

    // Demonstrate that fewer than t shares cannot reconstruct
    println!("\n--- Step 3: Attempting Reconstruction with Insufficient Shares ---");
    if threshold > 1 {
        let insufficient_shares = &shares[0..threshold - 1];
        println!(
            "Attempting to reconstruct with only {} shares (need {})...",
            insufficient_shares.len(),
            threshold
        );

        match scheme.reconstruct(insufficient_shares) {
            Ok(_) => println!("✗ Error: Should have failed!"),
            Err(e) => println!("✓ Correctly failed: {}", e),
        }
    }

    // Demonstrate reconstruction with all shares
    println!("\n--- Step 4: Reconstructing with All Shares ---");
    let reconstructed_all = scheme.reconstruct(&shares)?;
    println!("Reconstructed secret: {}", reconstructed_all.value());
    assert_eq!(reconstructed_all.value(), secret.value());
    println!("✓ Success!");

    Ok(())
}

/// Generate unique random indices from 0 to max-1
fn generate_unique_random_indices(max: u64, count: usize) -> Vec<u64> {
    let mut rng = rand::rng();
    let mut indices = Vec::new();

    while indices.len() < count {
        let random_index = rng.random_range(0..max);
        if !indices.contains(&random_index) {
            indices.push(random_index);
        }
    }

    indices
}
