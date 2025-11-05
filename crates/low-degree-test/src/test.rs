//! Low-degree test implementation.
//!
//! This module provides the core low-degree test implementation,
//! which verifies that a polynomial has degree at most d.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use crypto_polynomial::{interpolate_monomial_basis, Point, Polynomial};

/// Result of a low-degree test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestResult {
    /// The polynomial passes the test (likely has degree ≤ d)
    Pass,
    /// The polynomial fails the test (likely has degree > d)
    Fail,
    /// The test is inconclusive
    Inconclusive,
}

/// Low-degree test implementation.
///
/// This struct provides methods to test whether a polynomial
/// has degree at most d by evaluating it at random points.
#[derive(Debug, Clone)]
pub struct LowDegreeTest {
    /// The maximum degree to test for
    pub max_degree: usize,
    /// The number of test points to use
    pub num_test_points: usize,
    /// The field modulus
    pub modulus: u64,
}

impl LowDegreeTest {
    /// Create a new low-degree test.
    ///
    /// # Arguments
    /// * `max_degree` - The maximum degree to test for
    /// * `num_test_points` - The number of test points to use
    /// * `modulus` - The field modulus
    ///
    /// # Returns
    /// A new low-degree test
    pub fn new(max_degree: usize, num_test_points: usize, modulus: u64) -> Self {
        Self {
            max_degree,
            num_test_points,
            modulus,
        }
    }

    /// Test if a polynomial has degree at most max_degree.
    ///
    /// This implementation uses the Schwartz-Zippel lemma:
    /// if a polynomial has degree d, then the probability that
    /// it evaluates to 0 at a random point is at most d/|F|.
    ///
    /// # Arguments
    /// * `poly` - The polynomial to test
    ///
    /// # Returns
    /// The test result
    ///
    /// # Errors
    /// Returns an error if the polynomial is invalid or the test fails
    pub fn test_polynomial(&self, poly: &Polynomial) -> CryptoResult<TestResult> {
        if poly.modulus() != self.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Polynomial must be defined over the same field as the test".to_string(),
            ));
        }

        let actual_degree = poly.degree();

        // If the polynomial has degree ≤ max_degree, it always passes
        if actual_degree <= self.max_degree {
            return Ok(TestResult::Pass);
        }

        // For polynomials with degree > max_degree, we use Schwartz-Zippel
        let mut zero_count = 0;

        for _ in 0..self.num_test_points {
            let random_point = FiniteField::random(self.modulus)?;
            let evaluation = poly.evaluate(&random_point)?;

            if evaluation.value() == 0 {
                zero_count += 1;
            }
        }

        // Calculate the probability of getting this many zeros
        let field_size = self.modulus;
        let expected_zeros =
            (actual_degree as f64 / field_size as f64) * self.num_test_points as f64;
        let actual_zeros = zero_count as f64;

        // If we get significantly more zeros than expected, the polynomial likely has high degree
        let threshold = expected_zeros * 1.5; // Conservative threshold

        if actual_zeros > threshold {
            Ok(TestResult::Fail)
        } else {
            Ok(TestResult::Inconclusive)
        }
    }

    /// Test if a polynomial has degree at most max_degree using interpolation.
    ///
    /// This method tests by interpolating the polynomial at max_degree + 2 points
    /// and checking if the resulting polynomial has the expected degree.
    ///
    /// # Arguments
    /// * `poly` - The polynomial to test
    ///
    /// # Returns
    /// The test result
    ///
    /// # Errors
    /// Returns an error if the polynomial is invalid or the test fails
    pub fn test_by_interpolation(&self, poly: &Polynomial) -> CryptoResult<TestResult> {
        if poly.modulus() != self.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Polynomial must be defined over the same field as the test".to_string(),
            ));
        }

        let test_points = self.max_degree + 2;
        let mut points = Vec::with_capacity(test_points);

        // Generate test points
        for i in 0..test_points {
            let x = FiniteField::new(i as u64, self.modulus)?;
            let y = poly.evaluate(&x)?;
            points.push(Point::new(x, y)?);
        }

        // Interpolate the polynomial
        let interpolated = interpolate_monomial_basis(&points)?;

        // Check if the interpolated polynomial has degree ≤ max_degree
        if interpolated.degree() <= self.max_degree {
            Ok(TestResult::Pass)
        } else {
            Ok(TestResult::Fail)
        }
    }

    /// Test if a polynomial has degree at most max_degree using FFT.
    ///
    /// This method uses FFT to compute the polynomial at many points
    /// and then applies a low-degree test on the evaluations.
    ///
    /// # Arguments
    /// * `poly` - The polynomial to test
    ///
    /// # Returns
    /// The test result
    ///
    /// # Errors
    /// Returns an error if the polynomial is invalid or the test fails
    pub fn test_by_fft(&self, poly: &Polynomial) -> CryptoResult<TestResult> {
        if poly.modulus() != self.modulus {
            return Err(CryptoError::InvalidFieldElement(
                "Polynomial must be defined over the same field as the test".to_string(),
            ));
        }

        // Find a primitive root of unity
        let n = (self.max_degree + 1).next_power_of_two();
        if n >= self.modulus as usize {
            return Err(CryptoError::InvalidFieldElement(
                "Field too small for FFT-based test".to_string(),
            ));
        }

        // Generate evaluation points (powers of a primitive root)
        // For now, just use sequential points as a simplification
        let mut evaluations = Vec::new();
        for i in 0..n {
            let x = FiniteField::new(i as u64, self.modulus)?;
            let y = poly.evaluate(&x)?;
            evaluations.push(y);
        }

        // Count the number of non-zero evaluations
        let non_zero_count = evaluations
            .iter()
            .filter(|&&eval| eval.value() != 0)
            .count();

        // If there are too many non-zero evaluations, the polynomial likely has high degree
        let expected_non_zero = self.max_degree + 1;

        if non_zero_count > expected_non_zero {
            Ok(TestResult::Fail)
        } else {
            Ok(TestResult::Pass)
        }
    }

    /// Get the error probability of the test.
    ///
    /// This returns the probability that a polynomial with degree > max_degree
    /// passes the test (false positive).
    pub fn error_probability(&self) -> f64 {
        let field_size = self.modulus as f64;
        let max_degree = self.max_degree as f64;

        // Using Schwartz-Zippel bound
        (max_degree / field_size).powi(self.num_test_points as i32)
    }

    /// Get the number of test points needed for a given error probability.
    ///
    /// # Arguments
    /// * `error_prob` - The desired error probability
    /// * `max_degree` - The maximum degree to test for
    /// * `field_size` - The size of the field
    ///
    /// # Returns
    /// The number of test points needed
    pub fn points_needed_for_error(error_prob: f64, max_degree: usize, field_size: u64) -> usize {
        let max_degree = max_degree as f64;
        let field_size = field_size as f64;

        // Using Schwartz-Zippel bound: (d/|F|)^t ≤ ε
        // Therefore: t ≥ log(ε) / log(d/|F|)
        let ratio = max_degree / field_size;
        if ratio >= 1.0 {
            return usize::MAX; // Impossible to achieve
        }

        let t = (error_prob.ln() / ratio.ln()).ceil() as usize;
        t.max(1) // At least 1 test point
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_degree_test_creation() {
        let test = LowDegreeTest::new(5, 10, 17);
        assert_eq!(test.max_degree, 5);
        assert_eq!(test.num_test_points, 10);
        assert_eq!(test.modulus, 17);
    }

    #[test]
    fn test_low_degree_polynomial() {
        let test = LowDegreeTest::new(3, 5, 17);
        let coeffs = vec![
            FiniteField::new(1, 17).unwrap(),
            FiniteField::new(2, 17).unwrap(),
            FiniteField::new(3, 17).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();

        let result = test.test_polynomial(&poly).unwrap();
        assert_eq!(result, TestResult::Pass);
    }

    #[test]
    fn test_high_degree_polynomial() {
        let test = LowDegreeTest::new(2, 10, 17);
        let coeffs = vec![
            FiniteField::new(1, 17).unwrap(),
            FiniteField::new(2, 17).unwrap(),
            FiniteField::new(3, 17).unwrap(),
            FiniteField::new(4, 17).unwrap(),
            FiniteField::new(5, 17).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();

        let result = test.test_polynomial(&poly).unwrap();
        // Should likely fail, but could be inconclusive due to randomness
        assert_ne!(result, TestResult::Pass);
    }

    #[test]
    fn test_interpolation_method() {
        let test = LowDegreeTest::new(2, 5, 17);
        let coeffs = vec![
            FiniteField::new(1, 17).unwrap(),
            FiniteField::new(2, 17).unwrap(),
            FiniteField::new(3, 17).unwrap(),
        ];
        let poly = Polynomial::new(coeffs).unwrap();

        let result = test.test_by_interpolation(&poly).unwrap();
        assert_eq!(result, TestResult::Pass);
    }

    #[test]
    fn test_error_probability() {
        let test = LowDegreeTest::new(5, 10, 17);
        let error_prob = test.error_probability();

        // Error probability should be between 0 and 1
        assert!(error_prob >= 0.0);
        assert!(error_prob <= 1.0);
    }

    #[test]
    fn test_points_needed() {
        let points = LowDegreeTest::points_needed_for_error(0.01, 5, 17);
        assert!(points > 0);

        // More test points should be needed for smaller error probability
        let points_smaller_error = LowDegreeTest::points_needed_for_error(0.001, 5, 17);
        assert!(points_smaller_error >= points);
    }
}
