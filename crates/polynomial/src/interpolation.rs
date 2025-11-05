//! Polynomial interpolation over finite fields.
//! 
//! This module provides implementations of polynomial interpolation
//! algorithms, including Lagrange interpolation.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use super::univariate::Polynomial;

/// Represents a point in a finite field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    /// The x-coordinate of the point
    pub x: FiniteField,
    /// The y-coordinate of the point
    pub y: FiniteField,
}

impl Point {
    /// Create a new point.
    /// 
    /// # Arguments
    /// * `x` - The x-coordinate
    /// * `y` - The y-coordinate
    /// 
    /// # Returns
    /// A new point
    pub fn new(x: FiniteField, y: FiniteField) -> CryptoResult<Self> {
        if x.modulus() != y.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Point coordinates must belong to the same field".to_string()
            ));
        }
        
        Ok(Self { x, y })
    }
    
    /// Get the modulus of the field this point belongs to.
    pub fn modulus(&self) -> u64 {
        self.x.modulus()
    }
}

/// Compute the Lagrange basis polynomial delta_j(X) evaluated at a point.
///
/// This function computes the j-th Lagrange basis polynomial evaluated at point T.
/// The Lagrange basis polynomial is defined as:
/// δ_j(X) = ∏(i≠j) (X - x_i) / (x_j - x_i)
///
/// This is useful for educational purposes to explicitly see how Lagrange basis
/// polynomials are constructed.
///
/// # Arguments
/// * `points` - The interpolation points
/// * `j` - The index of the basis polynomial to compute (0-indexed)
/// * `eval_point` - The point at which to evaluate the basis polynomial
///
/// # Returns
/// * The value of δ_j(eval_point)
///
/// # Errors
/// * Returns an error if j is out of bounds or fields don't match
///
/// # Examples
/// ```
/// use crypto_polynomial::interpolation::{Point, generate_delta};
/// use crypto_field::FiniteField;
///
/// let points = vec![
///     Point::new(FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()).unwrap(),
///     Point::new(FiniteField::new(2, 7).unwrap(), FiniteField::new(4, 7).unwrap()).unwrap(),
/// ];
/// let eval_point = FiniteField::new(3, 7).unwrap();
/// let delta = generate_delta(&points, 0, eval_point).unwrap();
/// ```
pub fn generate_delta(
    points: &[Point],
    j: usize,
    eval_point: FiniteField
) -> CryptoResult<FiniteField> {
    if points.is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }

    if j >= points.len() {
        return Err(CryptoError::InvalidFieldElement(
            format!("Index {} is out of bounds for {} points", j, points.len())
        ));
    }

    let modulus = points[0].modulus();
    if eval_point.modulus() != modulus {
        return Err(CryptoError::InvalidFieldElement(
            "Evaluation point must belong to the same field as interpolation points".to_string()
        ));
    }

    let x_j = points[j].x;
    let mut delta = FiniteField::new(1, modulus)?;

    for (i, point) in points.iter().enumerate() {
        if i == j {
            continue;
        }

        let x_i = point.x;
        let numerator = eval_point.sub(&x_i)?;
        let denominator = x_j.sub(&x_i)?;
        delta = delta.mul(&numerator)?.div(&denominator)?;
    }

    Ok(delta)
}

/// Evaluate a polynomial at a point using the given interpolation points.
/// 
/// This function uses the Lagrange interpolation formula to evaluate
/// the polynomial at the given point.
/// 
/// # Arguments
/// * `points` - The interpolation points
/// * `point` - The point to evaluate at
/// 
/// # Returns
/// The value of the polynomial at the given point
/// 
/// # Errors
/// Returns an error if the points are invalid or the point belongs to a different field
pub fn evaluate_polynomial(points: &[Point], point: FiniteField) -> CryptoResult<FiniteField> {
    if points.is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }
    
    let modulus = points[0].modulus();
    if point.modulus() != modulus {
        return Err(CryptoError::InvalidFieldElement(
            "Point must belong to the same field as interpolation points".to_string()
        ));
    }
    
    let n = points.len();
    let mut result = FiniteField::new(0, modulus)?;
    
    for i in 0..n {
        let mut delta = FiniteField::new(1, modulus)?;
        
        for j in 0..n {
            if i == j {
                continue;
            }
            
            let num = point.sub(&points[j].x)?;
            let den = points[i].x.sub(&points[j].x)?;
            delta = delta.mul(&num)?.div(&den)?;
        }
        
        let term = points[i].y.mul(&delta)?;
        result = result.add(&term)?;
    }
    
    Ok(result)
}

/// Construct a polynomial in monomial basis using Lagrange interpolation.
/// 
/// This function constructs the Vandermonde matrix and solves the linear system
/// to find the coefficients in monomial basis.
/// 
/// # Arguments
/// * `points` - The interpolation points
/// 
/// # Returns
/// The interpolated polynomial in monomial basis
/// 
/// # Errors
/// Returns an error if the points are invalid or the system is singular
pub fn interpolate_monomial_basis(points: &[Point]) -> CryptoResult<Polynomial> {
    if points.is_empty() {
        return Err(CryptoError::InvalidDegree(0));
    }
    
    let n = points.len();
    let modulus = points[0].modulus();
    
    // Ensure all points belong to the same field
    for point in points {
        if point.modulus() != modulus {
            return Err(CryptoError::InvalidFieldElement(
                "All points must belong to the same field".to_string()
            ));
        }
    }
    
    // Construct Vandermonde matrix and RHS
    let mut vandermonde = vec![vec![FiniteField::new(0, modulus)?; n]; n];
    let mut rhs = vec![FiniteField::new(0, modulus)?; n];
    
    for i in 0..n {
        let mut power = FiniteField::new(1, modulus)?;
        for j in 0..n {
            vandermonde[i][j] = power;
            power = power.mul(&points[i].x)?;
        }
        rhs[i] = points[i].y;
    }
    
    // Solve V * coeffs = rhs
    let coeffs = solve_linear_system(vandermonde, rhs)?;
    Polynomial::new(coeffs)
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
    mut rhs: Vec<FiniteField>
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
            return Err(CryptoError::InterpolationError("Singular matrix".to_string()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_creation() {
        let x = FiniteField::new(1, 7).unwrap();
        let y = FiniteField::new(2, 7).unwrap();
        let point = Point::new(x, y).unwrap();
        assert_eq!(point.x.value(), 1);
        assert_eq!(point.y.value(), 2);
        assert_eq!(point.modulus(), 7);
    }

    #[test]
    fn test_interpolation() {
        let points = vec![
            Point::new(FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()).unwrap(),
            Point::new(FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()).unwrap(),
            Point::new(FiniteField::new(2, 7).unwrap(), FiniteField::new(4, 7).unwrap()).unwrap(),
        ];
        
        let poly = interpolate_monomial_basis(&points).unwrap();
        assert_eq!(poly.degree(), 2);
        
        // Test evaluation at interpolation points
        for point in &points {
            let eval = poly.evaluate(&point.x).unwrap();
            assert_eq!(eval.value(), point.y.value());
        }
    }

    #[test]
    fn test_evaluate_polynomial() {
        let points = vec![
            Point::new(FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()).unwrap(),
            Point::new(FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()).unwrap(),
        ];
        
        let point = FiniteField::new(3, 7).unwrap();
        let result = evaluate_polynomial(&points, point).unwrap();
        // The interpolated polynomial should be 1 + x, so at x=3: 1 + 3 = 4
        assert_eq!(result.value(), 4);
    }
} 