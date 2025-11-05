//! Matrix implementation for Frievalds algorithm.
//! 
//! This module provides a matrix implementation optimized for
//! the Frievalds algorithm for matrix multiplication verification.

use crypto_core::{CryptoError, CryptoResult};
use crypto_field::FiniteField;
use thiserror::Error;

/// Error type for matrix operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MatrixError {
    #[error("Invalid matrix dimensions: {0}")]
    InvalidDimensions(String),
    #[error("Matrix multiplication dimension mismatch: {0}")]
    DimensionMismatch(String),
    #[error("Index out of bounds: row={row}, col={col}, rows={rows}, cols={cols}")]
    IndexOutOfBounds { row: usize, col: usize, rows: usize, cols: usize },
    #[error("Field error: {0}")]
    FieldError(String),
}

/// Represents a matrix over a finite field.
/// 
/// This struct provides efficient matrix operations needed for
/// the Frievalds algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrix {
    /// The matrix elements stored in row-major order
    pub elements: Vec<Vec<FiniteField>>,
    /// Number of rows
    pub rows: usize,
    /// Number of columns
    pub cols: usize,
}

impl Matrix {
    /// Create a new matrix from a 2D vector of field elements.
    /// 
    /// # Arguments
    /// * `elements` - The matrix elements
    /// 
    /// # Returns
    /// A new matrix
    /// 
    /// # Errors
    /// Returns an error if the matrix is invalid
    pub fn new(elements: Vec<Vec<FiniteField>>) -> CryptoResult<Self> {
        if elements.is_empty() {
            return Err(CryptoError::InvalidFieldElement(
                "Matrix cannot be empty".to_string()
            ));
        }
        
        let rows = elements.len();
        let cols = elements[0].len();
        
        if cols == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Matrix cannot have empty rows".to_string()
            ));
        }
        
        // Check that all rows have the same length
        for (i, row) in elements.iter().enumerate() {
            if row.len() != cols {
                return Err(CryptoError::InvalidFieldElement(
                    format!("Row {} has length {}, expected {}", i, row.len(), cols)
                ));
            }
        }
        
        // Check that all elements belong to the same field
        let modulus = elements[0][0].modulus();
        for row in &elements {
            for element in row {
                if element.modulus() != modulus {
                    return Err(CryptoError::InvalidFieldElement(
                        "All matrix elements must belong to the same field".to_string()
                    ));
                }
            }
        }
        
        Ok(Self { elements, rows, cols })
    }
    
    /// Create a zero matrix of the given dimensions.
    /// 
    /// # Arguments
    /// * `rows` - Number of rows
    /// * `cols` - Number of columns
    /// * `modulus` - Field modulus
    /// 
    /// # Returns
    /// A zero matrix
    /// 
    /// # Errors
    /// Returns an error if the dimensions are invalid
    pub fn zero(rows: usize, cols: usize, modulus: u64) -> CryptoResult<Self> {
        if rows == 0 || cols == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Matrix dimensions must be positive".to_string()
            ));
        }
        
        let mut elements = Vec::with_capacity(rows);
        for _ in 0..rows {
            let mut row = Vec::with_capacity(cols);
            for _ in 0..cols {
                row.push(FiniteField::new(0, modulus)?);
            }
            elements.push(row);
        }
        
        Ok(Self { elements, rows, cols })
    }
    
    /// Create an identity matrix of the given size.
    /// 
    /// # Arguments
    /// * `size` - The size of the identity matrix
    /// * `modulus` - Field modulus
    /// 
    /// # Returns
    /// An identity matrix
    /// 
    /// # Errors
    /// Returns an error if the size is invalid
    pub fn identity(size: usize, modulus: u64) -> CryptoResult<Self> {
        if size == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Identity matrix size must be positive".to_string()
            ));
        }
        
        let mut elements = Vec::with_capacity(size);
        for i in 0..size {
            let mut row = Vec::with_capacity(size);
            for j in 0..size {
                let value = if i == j { 1 } else { 0 };
                row.push(FiniteField::new(value, modulus)?);
            }
            elements.push(row);
        }
        
        Ok(Self { elements, rows: size, cols: size })
    }
    
    /// Create a random matrix of the given dimensions.
    /// 
    /// # Arguments
    /// * `rows` - Number of rows
    /// * `cols` - Number of columns
    /// * `modulus` - Field modulus
    /// 
    /// # Returns
    /// A random matrix
    /// 
    /// # Errors
    /// Returns an error if the dimensions are invalid
    pub fn random(rows: usize, cols: usize, modulus: u64) -> CryptoResult<Self> {
        if rows == 0 || cols == 0 {
            return Err(CryptoError::InvalidFieldElement(
                "Matrix dimensions must be positive".to_string()
            ));
        }
        
        let mut elements = Vec::with_capacity(rows);
        for _ in 0..rows {
            let mut row = Vec::with_capacity(cols);
            for _ in 0..cols {
                row.push(FiniteField::random(modulus)?);
            }
            elements.push(row);
        }
        
        Ok(Self { elements, rows, cols })
    }
    
    /// Get the element at the specified position.
    /// 
    /// # Arguments
    /// * `row` - Row index (0-indexed)
    /// * `col` - Column index (0-indexed)
    /// 
    /// # Returns
    /// The element at the specified position
    /// 
    /// # Errors
    /// Returns an error if the indices are out of bounds
    pub fn get(&self, row: usize, col: usize) -> CryptoResult<FiniteField> {
        if row >= self.rows || col >= self.cols {
            return Err(CryptoError::InvalidFieldElement(
                format!("Index ({}, {}) out of bounds for matrix of size {}x{}", 
                       row, col, self.rows, self.cols)
            ));
        }
        
        Ok(self.elements[row][col])
    }
    
    /// Set the element at the specified position.
    /// 
    /// # Arguments
    /// * `row` - Row index (0-indexed)
    /// * `col` - Column index (0-indexed)
    /// * `value` - The new value
    /// 
    /// # Errors
    /// Returns an error if the indices are out of bounds or the value belongs to a different field
    pub fn set(&mut self, row: usize, col: usize, value: FiniteField) -> CryptoResult<()> {
        if row >= self.rows || col >= self.cols {
            return Err(CryptoError::InvalidFieldElement(
                format!("Index ({}, {}) out of bounds for matrix of size {}x{}", 
                       row, col, self.rows, self.cols)
            ));
        }
        
        if value.modulus() != self.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Value must belong to the same field as the matrix".to_string()
            ));
        }
        
        self.elements[row][col] = value;
        Ok(())
    }
    
    /// Get the modulus of the field this matrix is defined over.
    pub fn modulus(&self) -> u64 {
        if self.elements.is_empty() || self.elements[0].is_empty() {
            0
        } else {
            self.elements[0][0].modulus()
        }
    }
    
    /// Check if this matrix is square.
    pub fn is_square(&self) -> bool {
        self.rows == self.cols
    }
    
    /// Check if this matrix is the zero matrix.
    pub fn is_zero(&self) -> bool {
        self.elements.iter().all(|row| {
            row.iter().all(|&element| element.value() == 0)
        })
    }
    
    /// Check if this matrix is the identity matrix.
    pub fn is_identity(&self) -> bool {
        if !self.is_square() {
            return false;
        }
        
        for i in 0..self.rows {
            for j in 0..self.cols {
                let expected = if i == j { 1 } else { 0 };
                if self.elements[i][j].value() != expected {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Add two matrices.
    /// 
    /// # Arguments
    /// * `other` - The other matrix to add
    /// 
    /// # Returns
    /// The sum of the two matrices
    /// 
    /// # Errors
    /// Returns an error if the matrices have different dimensions or fields
    pub fn add(&self, other: &Self) -> CryptoResult<Self> {
        if self.rows != other.rows || self.cols != other.cols {
            return Err(CryptoError::InvalidFieldElement(
                format!("Cannot add matrices of different dimensions: {}x{} and {}x{}", 
                       self.rows, self.cols, other.rows, other.cols)
            ));
        }
        
        if self.modulus() != other.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Matrices must be defined over the same field".to_string()
            ));
        }
        
        let mut result_elements = Vec::with_capacity(self.rows);
        for i in 0..self.rows {
            let mut row = Vec::with_capacity(self.cols);
            for j in 0..self.cols {
                let sum = self.elements[i][j].add(&other.elements[i][j])?;
                row.push(sum);
            }
            result_elements.push(row);
        }
        
        Self::new(result_elements)
    }
    
    /// Multiply two matrices.
    /// 
    /// # Arguments
    /// * `other` - The other matrix to multiply
    /// 
    /// # Returns
    /// The product of the two matrices
    /// 
    /// # Errors
    /// Returns an error if the matrices have incompatible dimensions or different fields
    pub fn mul(&self, other: &Self) -> CryptoResult<Self> {
        if self.cols != other.rows {
            return Err(CryptoError::InvalidFieldElement(
                format!("Cannot multiply matrices: {}x{} and {}x{}", 
                       self.rows, self.cols, other.rows, other.cols)
            ));
        }
        
        if self.modulus() != other.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Matrices must be defined over the same field".to_string()
            ));
        }
        
        let mut result_elements = Vec::with_capacity(self.rows);
        for i in 0..self.rows {
            let mut row = Vec::with_capacity(other.cols);
            for j in 0..other.cols {
                let mut sum = FiniteField::new(0, self.modulus())?;
                for k in 0..self.cols {
                    let product = self.elements[i][k].mul(&other.elements[k][j])?;
                    sum = sum.add(&product)?;
                }
                row.push(sum);
            }
            result_elements.push(row);
        }
        
        Self::new(result_elements)
    }
    
    /// Multiply a matrix by a vector.
    /// 
    /// # Arguments
    /// * `vector` - The vector to multiply by
    /// 
    /// # Returns
    /// The product of the matrix and vector
    /// 
    /// # Errors
    /// Returns an error if the dimensions are incompatible or the vector belongs to a different field
    pub fn mul_vector(&self, vector: &[FiniteField]) -> CryptoResult<Vec<FiniteField>> {
        if self.cols != vector.len() {
            return Err(CryptoError::InvalidFieldElement(
                format!("Cannot multiply matrix {}x{} by vector of length {}", 
                       self.rows, self.cols, vector.len())
            ));
        }
        
        if !vector.is_empty() && vector[0].modulus() != self.modulus() {
            return Err(CryptoError::InvalidFieldElement(
                "Vector must belong to the same field as the matrix".to_string()
            ));
        }
        
        let mut result = Vec::with_capacity(self.rows);
        for i in 0..self.rows {
            let mut sum = FiniteField::new(0, self.modulus())?;
            for j in 0..self.cols {
                let product = self.elements[i][j].mul(&vector[j])?;
                sum = sum.add(&product)?;
            }
            result.push(sum);
        }
        
        Ok(result)
    }
    
    /// Transpose the matrix.
    /// 
    /// # Returns
    /// The transposed matrix
    pub fn transpose(&self) -> Self {
        let mut transposed_elements = Vec::with_capacity(self.cols);
        for j in 0..self.cols {
            let mut row = Vec::with_capacity(self.rows);
            for i in 0..self.rows {
                row.push(self.elements[i][j]);
            }
            transposed_elements.push(row);
        }
        
        Self {
            elements: transposed_elements,
            rows: self.cols,
            cols: self.rows,
        }
    }
}

impl std::fmt::Display for Matrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Matrix({}x{}) [", self.rows, self.cols)?;
        
        for (i, row) in self.elements.iter().enumerate() {
            if i > 0 {
                write!(f, "; ")?;
            }
            for (j, &element) in row.iter().enumerate() {
                if j > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}", element)?;
            }
        }
        
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_creation() {
        let elements = vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ];
        
        let matrix = Matrix::new(elements).unwrap();
        assert_eq!(matrix.rows, 2);
        assert_eq!(matrix.cols, 2);
        assert_eq!(matrix.modulus(), 7);
    }

    #[test]
    fn test_zero_matrix() {
        let matrix = Matrix::zero(3, 4, 17).unwrap();
        assert_eq!(matrix.rows, 3);
        assert_eq!(matrix.cols, 4);
        assert!(matrix.is_zero());
    }

    #[test]
    fn test_identity_matrix() {
        let matrix = Matrix::identity(3, 17).unwrap();
        assert_eq!(matrix.rows, 3);
        assert_eq!(matrix.cols, 3);
        assert!(matrix.is_identity());
    }

    #[test]
    fn test_matrix_addition() {
        let a = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let b = Matrix::new(vec![
            vec![FiniteField::new(5, 7).unwrap(), FiniteField::new(6, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()],
        ]).unwrap();
        
        let sum = a.add(&b).unwrap();
        assert_eq!(sum.get(0, 0).unwrap().value(), 6); // 1 + 5 = 6
        assert_eq!(sum.get(0, 1).unwrap().value(), 1); // 2 + 6 = 8 ≡ 1 (mod 7)
    }

    #[test]
    fn test_matrix_multiplication() {
        let a = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let b = Matrix::new(vec![
            vec![FiniteField::new(5, 7).unwrap(), FiniteField::new(6, 7).unwrap()],
            vec![FiniteField::new(0, 7).unwrap(), FiniteField::new(1, 7).unwrap()],
        ]).unwrap();
        
        let product = a.mul(&b).unwrap();
        assert_eq!(product.get(0, 0).unwrap().value(), 5); // 1*5 + 2*0 = 5
        assert_eq!(product.get(0, 1).unwrap().value(), 1); // 1*6 + 2*1 = 8 ≡ 1 (mod 7)
    }

    #[test]
    fn test_matrix_vector_multiplication() {
        let matrix = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let vector = vec![
            FiniteField::new(5, 7).unwrap(),
            FiniteField::new(6, 7).unwrap(),
        ];
        
        let result = matrix.mul_vector(&vector).unwrap();
        assert_eq!(result[0].value(), 3); // 1*5 + 2*6 = 17 ≡ 3 (mod 7)
        assert_eq!(result[1].value(), 4); // 3*5 + 4*6 = 39 ≡ 4 (mod 7)
    }

    #[test]
    fn test_matrix_transpose() {
        let matrix = Matrix::new(vec![
            vec![FiniteField::new(1, 7).unwrap(), FiniteField::new(2, 7).unwrap()],
            vec![FiniteField::new(3, 7).unwrap(), FiniteField::new(4, 7).unwrap()],
        ]).unwrap();
        
        let transposed = matrix.transpose();
        assert_eq!(transposed.rows, 2);
        assert_eq!(transposed.cols, 2);
        assert_eq!(transposed.get(0, 1).unwrap().value(), 3);
        assert_eq!(transposed.get(1, 0).unwrap().value(), 2);
    }
} 