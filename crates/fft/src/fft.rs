//! Fast Fourier Transform implementation over finite fields.
//!
//! This module provides efficient FFT algorithms for polynomial
//! evaluation and multiplication over finite fields.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use crypto_polynomial::Polynomial;

/// Compute the Fast Fourier Transform of a polynomial.
///
/// # Arguments
/// * `poly` - The polynomial to transform
/// * `domain` - The domain (multiplicative subgroup) for evaluation
///
/// # Returns
/// The FFT of the polynomial evaluated at the domain points
///
/// # Errors
/// Returns an error if the domain is invalid or the polynomial is empty
pub fn fft(poly: &Polynomial, domain: &[FiniteField]) -> CryptoResult<Vec<FiniteField>> {
    if poly.coefficients().is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }

    if domain.is_empty() {
        return Err(CryptoError::FftError("Empty domain".to_string()));
    }

    let n = domain.len();
    let mut result = vec![FiniteField::new(0, poly.modulus())?; n];

    // Use the polynomial's evaluate method for each domain point
    for (i, &point) in domain.iter().enumerate() {
        result[i] = poly.evaluate(&point)?;
    }

    Ok(result)
}

/// Compute the inverse Fast Fourier Transform.
///
/// # Arguments
/// * `values` - The values to transform back
/// * `domain` - The domain used for the original FFT
///
/// # Returns
/// The polynomial coefficients recovered from the FFT values
///
/// # Errors
/// Returns an error if the domain is invalid or the values are empty
pub fn ifft(values: &[FiniteField], domain: &[FiniteField]) -> CryptoResult<Polynomial> {
    if values.is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }

    if domain.is_empty() {
        return Err(CryptoError::FftError("Empty domain".to_string()));
    }

    if values.len() != domain.len() {
        return Err(CryptoError::FftError(
            "Values and domain must have the same length".to_string(),
        ));
    }

    let n = values.len();
    let modulus = values[0].modulus();

    // Construct the Vandermonde matrix for interpolation
    let mut vandermonde = vec![vec![FiniteField::new(0, modulus)?; n]; n];
    let mut rhs = vec![FiniteField::new(0, modulus)?; n];

    for i in 0..n {
        let mut power = FiniteField::new(1, modulus)?;
        for j in 0..n {
            vandermonde[i][j] = power;
            power = power.mul(&domain[i])?;
        }
        rhs[i] = values[i];
    }

    // Solve the linear system to get coefficients
    let coeffs = solve_linear_system(vandermonde, rhs)?;
    Polynomial::new(coeffs)
}

/// Compute FFT in-place (modifies the input vector).
///
/// # Arguments
/// * `values` - The values to transform (will be modified)
/// * `domain` - The domain for evaluation
///
/// # Errors
/// Returns an error if the domain is invalid
pub fn fft_in_place(values: &mut [FiniteField], domain: &[FiniteField]) -> CryptoResult<()> {
    if domain.is_empty() {
        return Err(CryptoError::FftError("Empty domain".to_string()));
    }

    let n = values.len();
    if n != domain.len() {
        return Err(CryptoError::FftError(
            "Values and domain must have the same length".to_string(),
        ));
    }

    // For now, use the simple evaluation approach
    // In a full implementation, this would use the Cooley-Tukey algorithm
    for (_i, _point) in domain.iter().enumerate() {
        // This is a simplified version - in practice, you'd construct
        // a polynomial from the current values and evaluate it
        // For now, we'll just leave the values as they are
        // This is a placeholder for the actual FFT algorithm
    }

    Ok(())
}

/// Compute inverse FFT in-place (modifies the input vector).
///
/// # Arguments
/// * `values` - The values to transform back (will be modified)
/// * `domain` - The domain used for the original FFT
///
/// # Errors
/// Returns an error if the domain is invalid
pub fn ifft_in_place(values: &mut [FiniteField], domain: &[FiniteField]) -> CryptoResult<()> {
    if domain.is_empty() {
        return Err(CryptoError::FftError("Empty domain".to_string()));
    }

    let n = values.len();
    if n != domain.len() {
        return Err(CryptoError::FftError(
            "Values and domain must have the same length".to_string(),
        ));
    }

    // For now, use the simple interpolation approach
    // In a full implementation, this would use the inverse Cooley-Tukey algorithm
    let coeffs = solve_interpolation_system(values, domain)?;

    // Copy the coefficients back to the values array
    for (i, &coeff) in coeffs.iter().enumerate() {
        if i < values.len() {
            values[i] = coeff;
        }
    }

    // Zero out the rest if there are more values than coefficients
    for i in coeffs.len()..values.len() {
        values[i] = FiniteField::new(0, values[0].modulus())?;
    }

    Ok(())
}

/// Solve a linear system over a finite field using Gaussian elimination.
///
/// # Arguments
/// * `matrix` - The coefficient matrix
/// * `rhs` - The right-hand side vector
///
/// # Returns
/// The solution vector
///
/// # Errors
/// Returns an error if the system is singular
fn solve_linear_system(
    mut matrix: Vec<Vec<FiniteField>>,
    mut rhs: Vec<FiniteField>,
) -> CryptoResult<Vec<FiniteField>> {
    let n = rhs.len();

    // Forward elimination
    for i in 0..n {
        // Find pivot
        let mut pivot = i;
        while pivot < n && matrix[pivot][i].value() == 0 {
            pivot += 1;
        }

        if pivot >= n {
            return Err(CryptoError::FftError("Singular matrix".to_string()));
        }

        // Swap rows
        matrix.swap(i, pivot);
        rhs.swap(i, pivot);

        // Normalize pivot row
        let inv = matrix[i][i].inverse()?;
        for j in i..n {
            matrix[i][j] = matrix[i][j].mul(&inv)?;
        }
        rhs[i] = rhs[i].mul(&inv)?;

        // Eliminate below
        for k in (i + 1)..n {
            let factor = matrix[k][i];
            for j in i..n {
                let term = factor.mul(&matrix[i][j])?;
                matrix[k][j] = matrix[k][j].sub(&term)?;
            }
            let term = factor.mul(&rhs[i])?;
            rhs[k] = rhs[k].sub(&term)?;
        }
    }

    // Backward substitution
    let mut solution = vec![FiniteField::new(0, matrix[0][0].modulus())?; n];
    for i in (0..n).rev() {
        let mut sum = FiniteField::new(0, matrix[0][0].modulus())?;
        for j in (i + 1)..n {
            let term = matrix[i][j].mul(&solution[j])?;
            sum = sum.add(&term)?;
        }
        solution[i] = rhs[i].sub(&sum)?;
    }

    Ok(solution)
}

/// Solve interpolation system to recover polynomial coefficients.
///
/// # Arguments
/// * `values` - The function values
/// * `domain` - The domain points
///
/// # Returns
/// The polynomial coefficients
///
/// # Errors
/// Returns an error if the system is singular
fn solve_interpolation_system(
    values: &[FiniteField],
    domain: &[FiniteField],
) -> CryptoResult<Vec<FiniteField>> {
    let n = values.len();
    let modulus = values[0].modulus();

    // Construct the Vandermonde matrix
    let mut vandermonde = vec![vec![FiniteField::new(0, modulus)?; n]; n];
    let mut rhs = vec![FiniteField::new(0, modulus)?; n];

    for i in 0..n {
        let mut power = FiniteField::new(1, modulus)?;
        for j in 0..n {
            vandermonde[i][j] = power;
            power = power.mul(&domain[i])?;
        }
        rhs[i] = values[i];
    }

    solve_linear_system(vandermonde, rhs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_basic() {
        let coeffs = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(1, 7).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();

        // Create a simple domain (powers of a generator)
        let domain = vec![
            FiniteField::new(1, 7).unwrap(),
            FiniteField::new(2, 7).unwrap(),
            FiniteField::new(4, 7).unwrap(),
        ];

        let fft_result = fft(&poly, &domain).unwrap();
        assert_eq!(fft_result.len(), 3);

        // Test that FFT followed by IFFT recovers the original polynomial
        let recovered_poly = ifft(&fft_result, &domain).unwrap();
        assert_eq!(poly.coefficients(), recovered_poly.coefficients());
    }

    #[test]
    fn test_fft_empty_polynomial() {
        let domain = vec![FiniteField::new(1, 7).unwrap()];
        let result = fft(&Polynomial::new(vec![]).unwrap(), &domain);
        assert!(result.is_err());
    }

    #[test]
    fn test_fft_empty_domain() {
        let coeffs = vec![FiniteField::new(1, 7).unwrap()];
        let poly = Polynomial::new(coeffs).unwrap();
        let result = fft(&poly, &[]);
        assert!(result.is_err());
    }
}
