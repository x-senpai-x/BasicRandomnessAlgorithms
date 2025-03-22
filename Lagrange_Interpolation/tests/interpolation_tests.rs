use rs_encoding::prime_field::FiniteField;
use Lagrange_Interpolation::LagrangeInterpolation::{Point,generate_delta,evaluate_polynomial};

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a Point
    fn create_point(x: u64, y: u64, modulus: u64) -> Point {
        let x=FiniteField::new(x, modulus);
        let y=FiniteField::new(y, modulus);
        return Point::new(x,y);
    }

    #[test]
    fn test_generate_delta() {
        // Test with simple polynomial over F_11
        // Points: (1,1), (2,4), (3,9) representing y = x²
        let modulus = 11;
        let points = vec![
            create_point(1, 1, modulus),
            create_point(2, 4, modulus),
            create_point(3, 9, modulus)
        ];
        
        // Generate delta_0 evaluated at T=4
        let t = 3; // 3 points
        let j = 0; // delta_0
        let test_x = FiniteField::new(4, modulus);
        
        let delta_result = generate_delta(&points, modulus, t, j, test_x);
        
        // Expected: delta_0(4) = (4-2)(4-3)/((1-2)(1-3)) = 2*1/(-1*-2) = 2*1/2 = 1
        // In F_11: 2*1*6 = 12 ≡ 1 (mod 11) [where 6 is inverse of 2 in F_11]
        let expected = FiniteField::new(1, modulus);
        assert_eq!(delta_result.value, expected.value);
    }

    #[test]
    fn test_evaluate_polynomial_quadratic() {
        // Test with points from y = x² in F_11
        let modulus = 11;
        let points = vec![
            create_point(1, 1, modulus),
            create_point(2, 4, modulus),
            create_point(3, 9, modulus)
        ];
        
        // Evaluate at x = 4, should give 4² = 16 ≡ 5 (mod 11)
        let test_x = FiniteField::new(4, modulus);
        let result = evaluate_polynomial(points, test_x);
        
        let expected = FiniteField::new(5, modulus); // 16 mod 11 = 5
        assert_eq!(result.value, expected.value);
    }
    #[test]
    fn test_evaluate_polynomial_new() {
        // Test with points from y = x² in F_11
        let modulus = 8911377389942264203;
        let points = vec![
            create_point(4, 0, modulus),
            create_point(5, 0, modulus),
            create_point(3, 9, modulus)
        ];
        
        // Evaluate at x = 4, should give 4² = 16 ≡ 5 (mod 11)
        let test_x = FiniteField::new(4, modulus);
        let result = evaluate_polynomial(points, test_x);
        
        let expected = FiniteField::new(5, modulus); // 16 mod 11 = 5
        assert_eq!(result.value, expected.value);
    }

    #[test]
    fn test_evaluate_polynomial_linear() {
        // Test with points from y = 2x + 3 in F_17
        let modulus = 17;
        let points = vec![
            create_point(0, 3, modulus),
            create_point(1, 5, modulus),
            create_point(2, 7, modulus)
        ];
        
        // Evaluate at x = 5, should give 2*5 + 3 = 13
        let test_x = FiniteField::new(5, modulus);
        let result = evaluate_polynomial(points, test_x);
        
        let expected = FiniteField::new(13, modulus);
        assert_eq!(result.value, expected.value);
    }

    #[test]
    fn test_evaluate_polynomial_cubic() {
        // Test with points from y = x³ in F_23
        let modulus = 23;
        let points = vec![
            create_point(0, 0, modulus),
            create_point(1, 1, modulus),
            create_point(2, 8, modulus),
            create_point(3, 4, modulus) // 27 mod 23 = 4
        ];
        
        // Evaluate at x = 4, should give 4³ = 64 ≡ 18 (mod 23)
        let test_x = FiniteField::new(4, modulus);
        let result = evaluate_polynomial(points, test_x);
        
        let expected = FiniteField::new(18, modulus); // 64 mod 23 = 18
        assert_eq!(result.value, expected.value);
    }

    #[test]
    fn test_evaluate_polynomial_large_field() {
        // Test with large prime field F_1000000007
        let modulus = 1000000007;
        let points = vec![
            create_point(1, 100, modulus),
            create_point(2, 400, modulus),
            create_point(3, 900, modulus)
        ];
        
        // Should still correctly interpolate y = x²
        let test_x = FiniteField::new(4, modulus);
        let result = evaluate_polynomial(points, test_x);
        
        let expected = FiniteField::new(1600, modulus); // 4² = 16 * 100 = 1600
        assert_eq!(result.value, expected.value);
    }

    #[test]
    fn test_evaluate_polynomial_edge_cases() {
        // Test with one point (constant polynomial)
        let modulus = 11;
        let points = vec![
            create_point(5, 7, modulus)
        ];
        
        // Any input should give the same output
        let test_x = FiniteField::new(100, modulus);
        let result = evaluate_polynomial(points, test_x);
        
        let expected = FiniteField::new(7, modulus);
        assert_eq!(result.value, expected.value);
    }
}