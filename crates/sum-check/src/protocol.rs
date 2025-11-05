//! Sum-check protocol implementation.
//! 
//! This module provides the core sum-check protocol implementation,
//! which is used to verify the sum of a multivariate polynomial
//! over the boolean hypercube.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use crypto_polynomial::{Polynomial, Point, interpolate_monomial_basis, evaluate_polynomial};
use super::polynomial::MultiVariatePolynomial;

/// Represents a message sent in a round of the sum-check protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SumCheckRoundMessage {
    /// The univariate polynomial sent by the prover
    pub polynomial: Polynomial,
    /// The claimed sum for this round
    pub claimed_sum: FiniteField,
}

/// Execute the sum-check protocol for a given multivariate polynomial.
/// 
/// This function implements the sum-check protocol to verify that the sum
/// of a multivariate polynomial over the boolean hypercube equals a claimed value.
/// 
/// # Arguments
/// * `poly` - The multivariate polynomial to verify
/// 
/// # Returns
/// True if the protocol succeeds (the sum is correct), false otherwise
/// 
/// # Errors
/// Returns an error if the polynomial is invalid or the protocol fails
pub fn sum_check_protocol(poly: &MultiVariatePolynomial) -> CryptoResult<bool> {
    let modulus = poly.modulus();
    let num_vars = poly.num_variables();
    
    if num_vars == 0 {
        return Err(CryptoError::InvalidDegree(0));
    }
    
    let mut claimed_sum = poly.evaluate_sum()?;
    let mut r: Vec<FiniteField> = Vec::new(); // Random values chosen by verifier
    
    println!("Initial claimed sum over Boolean hypercube: {:?}", claimed_sum);
    
    let degrees = poly.degree_variables();
    
    for round in 0..num_vars {
        // Construct univariate polynomial g_v(X_v) := sum over x_{v+1} to x_n of g(r_1,...,r_{v-1}, X_v, x_{v+1},...,x_n)
        let mut points: Vec<Point> = Vec::new();
        
        for x in 0..=degrees[round] as usize {
            let mut input: Vec<FiniteField> = r.clone();
            input.push(FiniteField::new(x as u64, modulus)?);
            
            // Fill remaining variables with all possible 2^{n - (v+1)} binary values and sum evaluations
            let remaining = num_vars - (round + 1);
            let hypercube = FiniteField::boolean_hypercube(&FiniteField::new(0, modulus)?, remaining);
            let mut eval_sum = FiniteField::new(0, modulus)?;
            
            for suffix in hypercube.iter() {
                let mut full_input = input.clone();
                full_input.extend_from_slice(suffix);
                let val = poly.evaluate_point(&full_input)?;
                eval_sum = eval_sum.add(&val)?;
            }
            
            points.push(Point::new(
                FiniteField::new(x as u64, modulus)?,
                eval_sum
            )?);
        }
        
        let univariate_poly = interpolate_monomial_basis(&points)?;
        
        // Verify that g_v(0) + g_v(1) == previous round claimed sum
        let univariate_poly_0 = evaluate_polynomial(&points, FiniteField::new(0, modulus)?)?;
        let univariate_poly_1 = evaluate_polynomial(&points, FiniteField::new(1, modulus)?)?;
        let sum_check = univariate_poly_0.add(&univariate_poly_1)?;
        
        if sum_check.value() != claimed_sum.value() {
            println!("Round {}: Rejected due to incorrect sum: {:?} != {:?}", round, sum_check, claimed_sum);
            return Ok(false);
        }
        
        println!("Round {}: Polynomial sent: {:?}", round, univariate_poly);
        
        // Verifier chooses a random point r_v and sends it to prover
        let r_v = FiniteField::random(modulus)?;
        println!("Round {}: Verifier chooses random r_{} = {:?}", round, round + 1, r_v);
        r.push(r_v);
        
        // Compute new claimed sum = g_v(r_v) for next round
        claimed_sum = univariate_poly.evaluate(&r_v)?;
    }
    
    // Final check
    let eval = poly.evaluate_point(&r)?;
    if eval.value() != claimed_sum.value() {
        println!("Final check failed: g({:?}) = {:?} != {:?}", r, eval, claimed_sum);
        return Ok(false);
    }
    
    println!("Sum-check protocol succeeded. Verifier accepts.");
    Ok(true)
}

/// Execute a single round of the sum-check protocol.
/// 
/// This function implements a single round of the sum-check protocol,
/// where the prover sends a univariate polynomial and the verifier
/// checks the sum constraint.
/// 
/// # Arguments
/// * `poly` - The multivariate polynomial
/// * `round` - The current round number (0-indexed)
/// * `r` - The random values chosen in previous rounds
/// 
/// # Returns
/// The round message containing the polynomial and claimed sum
/// 
/// # Errors
/// Returns an error if the round computation fails
pub fn sum_check_round(
    poly: &MultiVariatePolynomial,
    round: usize,
    r: &[FiniteField]
) -> CryptoResult<SumCheckRoundMessage> {
    let modulus = poly.modulus();
    let num_vars = poly.num_variables();
    
    if round >= num_vars {
        return Err(CryptoError::InvalidDegree(round));
    }
    
    let degrees = poly.degree_variables();
    let mut points: Vec<Point> = Vec::new();
    
    for x in 0..=degrees[round] as usize {
        let mut input: Vec<FiniteField> = r.to_vec();
        input.push(FiniteField::new(x as u64, modulus)?);
        
        // Fill remaining variables with all possible binary values and sum evaluations
        let remaining = num_vars - (round + 1);
        let hypercube = FiniteField::boolean_hypercube(&FiniteField::new(0, modulus)?, remaining);
        let mut eval_sum = FiniteField::new(0, modulus)?;
        
        for suffix in hypercube.iter() {
            let mut full_input = input.clone();
            full_input.extend_from_slice(suffix);
            let val = poly.evaluate_point(&full_input)?;
            eval_sum = eval_sum.add(&val)?;
        }
        
        points.push(Point::new(
            FiniteField::new(x as u64, modulus)?,
            eval_sum
        )?);
    }
    
    let univariate_poly = interpolate_monomial_basis(&points)?;
    
    // Compute the claimed sum for this round
    let poly_0 = evaluate_polynomial(&points, FiniteField::new(0, modulus)?)?;
    let poly_1 = evaluate_polynomial(&points, FiniteField::new(1, modulus)?)?;
    let claimed_sum = poly_0.add(&poly_1)?;
    
    Ok(SumCheckRoundMessage {
        polynomial: univariate_poly,
        claimed_sum,
    })
}

/// Verify a single round of the sum-check protocol.
/// 
/// This function verifies a single round of the sum-check protocol
/// by checking that the polynomial satisfies the sum constraint.
/// 
/// # Arguments
/// * `message` - The round message from the prover
/// * `expected_sum` - The expected sum for this round
/// 
/// # Returns
/// True if the round verification succeeds, false otherwise
/// 
/// # Errors
/// Returns an error if the verification computation fails
pub fn verify_sum_check_round(
    message: &SumCheckRoundMessage,
    expected_sum: &FiniteField
) -> CryptoResult<bool> {
    let poly_0 = message.polynomial.evaluate(&FiniteField::new(0, message.polynomial.modulus())?)?;
    let poly_1 = message.polynomial.evaluate(&FiniteField::new(1, message.polynomial.modulus())?)?;
    let actual_sum = poly_0.add(&poly_1)?;
    
    Ok(actual_sum.value() == expected_sum.value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sum_check_protocol_simple() {
        // Create a simple polynomial: f(x₁, x₂) = x₁ + x₂
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(), // x₁
            FiniteField::new(1, 7).unwrap(), // x₂
        ];
        let degrees = vec![
            vec![1, 0], // x₁
            vec![0, 1], // x₂
        ];
        
        let poly = MultiVariatePolynomial::new(coeffs, degrees).unwrap();
        
        // The sum over {0,1} × {0,1} should be: f(0,0) + f(0,1) + f(1,0) + f(1,1) = 0 + 1 + 1 + 2 = 4
        let result = sum_check_protocol(&poly).unwrap();
        assert!(result);
    }

    #[test]
    fn test_sum_check_round() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
        ];
        let degrees = vec![
            vec![1, 0], // x₁
        ];
        
        let poly = MultiVariatePolynomial::new(coeffs, degrees).unwrap();
        let r: Vec<FiniteField> = vec![];
        
        let round_message = sum_check_round(&poly, 0, &r).unwrap();
        
        // Verify the round
        let expected_sum = FiniteField::new(1, 7).unwrap(); // Sum over x₂: 0 + 1 = 1
        let is_valid = verify_sum_check_round(&round_message, &expected_sum).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_sum_check_protocol_zero_polynomial() {
        let coeffs = vec![
            FiniteField::new(0, 7).unwrap(),
        ];
        let degrees = vec![
            vec![1, 1], // 0*x₁x₂
        ];
        
        let poly = MultiVariatePolynomial::new(coeffs, degrees).unwrap();
        let result = sum_check_protocol(&poly).unwrap();
        assert!(result);
    }
} 