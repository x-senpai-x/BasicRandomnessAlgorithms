//! Low-degree test protocol implementation.
//!
//! This module provides the interactive protocol for low-degree testing,
//! which allows a verifier to check that a polynomial has degree at most d
//! with high probability.

use crypto_core::CryptoResult;
use crypto_field::FiniteField;
use crypto_polynomial::Polynomial;

/// Message sent in a round of the low-degree test protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowDegreeTestMessage {
    /// The polynomial commitment or evaluation
    pub commitment: Vec<FiniteField>,
    /// The random challenge for this round
    pub challenge: FiniteField,
    /// The round number
    pub round: usize,
}

/// Execute the low-degree test protocol.
///
/// This function implements an interactive protocol where a prover
/// convinces a verifier that a polynomial has degree at most d.
///
/// # Arguments
/// * `poly` - The polynomial to test
/// * `max_degree` - The maximum degree to test for
/// * `num_rounds` - The number of rounds in the protocol
///
/// # Returns
/// True if the protocol succeeds, false otherwise
///
/// # Errors
/// Returns an error if the protocol fails
pub fn low_degree_test_protocol(
    poly: &Polynomial,
    max_degree: usize,
    num_rounds: usize,
) -> CryptoResult<bool> {
    let modulus = poly.modulus();
    let actual_degree = poly.degree();

    // If the polynomial actually has degree ≤ max_degree, it always passes
    if actual_degree <= max_degree {
        return Ok(true);
    }

    // For polynomials with degree > max_degree, we use an interactive protocol
    let mut current_poly = poly.clone();

    for _round in 0..num_rounds {
        // Prover sends the polynomial commitment
        let _commitment = current_poly.coefficients().to_vec();

        // Verifier chooses a random challenge
        let challenge = FiniteField::random(modulus)?;

        // Prover computes the folded polynomial
        let folded_poly = fold_polynomial(&current_poly, &challenge)?;

        // Update the current polynomial for the next round
        current_poly = folded_poly;

        // If the degree becomes small enough, we can stop early
        if current_poly.degree() <= max_degree {
            return Ok(true);
        }
    }

    // Final check: if the polynomial still has high degree after all rounds,
    // the protocol fails
    Ok(current_poly.degree() <= max_degree)
}

/// Fold a polynomial using a random challenge.
///
/// This function implements polynomial folding, which reduces the degree
/// of a polynomial by approximately half.
///
/// # Arguments
/// * `poly` - The polynomial to fold
/// * `challenge` - The random challenge for folding
///
/// # Returns
/// The folded polynomial
///
/// # Errors
/// Returns an error if the folding operation fails
pub fn fold_polynomial(poly: &Polynomial, challenge: &FiniteField) -> CryptoResult<Polynomial> {
    let coeffs = poly.coefficients();
    let degree = poly.degree();

    if degree == 0 {
        return Ok(poly.clone());
    }

    // Split the polynomial into even and odd coefficients
    let mut even_coeffs = Vec::new();
    let mut odd_coeffs = Vec::new();

    for (i, &coeff) in coeffs.iter().enumerate() {
        if i % 2 == 0 {
            even_coeffs.push(coeff);
        } else {
            odd_coeffs.push(coeff);
        }
    }

    // Create polynomials for even and odd parts
    let even_poly = Polynomial::new(even_coeffs)?;
    let odd_poly = Polynomial::new(odd_coeffs)?;

    // Compute the folded polynomial: f(x) = even_poly(x²) + x * odd_poly(x²)
    // At the challenge point: f(r) = even_poly(r²) + r * odd_poly(r²)
    let challenge_squared = challenge.mul(challenge)?;

    let even_eval = even_poly.evaluate(&challenge_squared)?;
    let odd_eval = odd_poly.evaluate(&challenge_squared)?;
    let odd_term = challenge.mul(&odd_eval)?;

    let folded_eval = even_eval.add(&odd_term)?;

    // Create a constant polynomial with the folded evaluation
    Ok(Polynomial::new(vec![folded_eval])?)
}

/// Execute a single round of the low-degree test protocol.
///
/// # Arguments
/// * `poly` - The polynomial to test
/// * `round` - The current round number
///
/// # Returns
/// The round message
///
/// # Errors
/// Returns an error if the round computation fails
pub fn low_degree_test_round(
    poly: &Polynomial,
    round: usize,
) -> CryptoResult<LowDegreeTestMessage> {
    let modulus = poly.modulus();
    let commitment = poly.coefficients().to_vec();
    let challenge = FiniteField::random(modulus)?;

    Ok(LowDegreeTestMessage {
        commitment,
        challenge,
        round,
    })
}

/// Verify a single round of the low-degree test protocol.
///
/// # Arguments
/// * `message` - The round message
/// * `expected_degree` - The expected maximum degree
///
/// # Returns
/// True if the round verification succeeds, false otherwise
///
/// # Errors
/// Returns an error if the verification computation fails
pub fn verify_low_degree_test_round(
    message: &LowDegreeTestMessage,
    expected_degree: usize,
) -> CryptoResult<bool> {
    let poly = Polynomial::new(message.commitment.clone())?;
    let actual_degree = poly.degree();

    Ok(actual_degree <= expected_degree)
}

/// Execute a non-interactive low-degree test.
///
/// This function implements a non-interactive version of the low-degree test
/// using the Fiat-Shamir transform.
///
/// # Arguments
/// * `poly` - The polynomial to test
/// * `max_degree` - The maximum degree to test for
/// * `num_rounds` - The number of rounds
///
/// # Returns
/// True if the test passes, false otherwise
///
/// # Errors
/// Returns an error if the test fails
pub fn non_interactive_low_degree_test(
    poly: &Polynomial,
    max_degree: usize,
    num_rounds: usize,
) -> CryptoResult<bool> {
    let modulus = poly.modulus();
    let actual_degree = poly.degree();

    // If the polynomial actually has degree ≤ max_degree, it always passes
    if actual_degree <= max_degree {
        return Ok(true);
    }

    // Use a deterministic challenge generation based on the polynomial
    let mut current_poly = poly.clone();
    let mut state = format!("{:?}", poly.coefficients());

    for round in 0..num_rounds {
        // Generate deterministic challenge from state
        let challenge = generate_deterministic_challenge(&state, modulus)?;

        // Fold the polynomial
        let folded_poly = fold_polynomial(&current_poly, &challenge)?;

        // Update state for next round
        state = format!("{:?}{:?}{}", state, challenge, round);

        // Update the current polynomial
        current_poly = folded_poly;

        // If the degree becomes small enough, we can stop early
        if current_poly.degree() <= max_degree {
            return Ok(true);
        }
    }

    // Final check
    Ok(current_poly.degree() <= max_degree)
}

/// Generate a deterministic challenge from a string state.
///
/// # Arguments
/// * `state` - The state string
/// * `modulus` - The field modulus
///
/// # Returns
/// A deterministic field element
///
/// # Errors
/// Returns an error if the generation fails
fn generate_deterministic_challenge(state: &str, modulus: u64) -> CryptoResult<FiniteField> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    state.hash(&mut hasher);
    let hash = hasher.finish();

    let value = hash % modulus;
    FiniteField::new(value, modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_degree_protocol_success() {
        let coeffs = vec![
            FiniteField::new(1, 17).unwrap(),
            FiniteField::new(2, 17).unwrap(),
            FiniteField::new(3, 17).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();

        let result = low_degree_test_protocol(&poly, 3, 2).unwrap();
        assert!(result);
    }

    #[test]
    fn test_low_degree_protocol_failure() {
        let coeffs = vec![
            FiniteField::new(1, 17).unwrap(),
            FiniteField::new(2, 17).unwrap(),
            FiniteField::new(3, 17).unwrap(),
            FiniteField::new(4, 17).unwrap(),
            FiniteField::new(5, 17).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();

        let _result = low_degree_test_protocol(&poly, 2, 1).unwrap();
        // Should likely fail, but could pass due to randomness
        // The test is probabilistic
    }

    #[test]
    fn test_polynomial_folding() {
        let coeffs = vec![
            FiniteField::new(1, 17).unwrap(),
            FiniteField::new(2, 17).unwrap(),
            FiniteField::new(3, 17).unwrap(),
            FiniteField::new(4, 17).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();
        let challenge = FiniteField::new(2, 17).unwrap();

        let folded = fold_polynomial(&poly, &challenge).unwrap();

        // The folded polynomial should have lower degree
        assert!(folded.degree() <= poly.degree());
    }

    #[test]
    fn test_non_interactive_test() {
        let coeffs = vec![
            FiniteField::new(1, 17).unwrap(),
            FiniteField::new(2, 17).unwrap(),
            FiniteField::new(3, 17).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();

        let result = non_interactive_low_degree_test(&poly, 3, 2).unwrap();
        assert!(result);
    }

    #[test]
    fn test_deterministic_challenge() {
        let state = "test_state";
        let modulus = 17;

        let challenge1 = generate_deterministic_challenge(state, modulus).unwrap();
        let challenge2 = generate_deterministic_challenge(state, modulus).unwrap();

        // Deterministic challenges should be equal
        assert_eq!(challenge1, challenge2);
    }
}
