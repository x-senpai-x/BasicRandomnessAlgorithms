mod prime_field;
use prime_field:: FiniteField;
mod utils;
// use utils::is_prime;
fn main() {
    let n:usize=3;
    let coeffecients=FiniteField::generate_vector_with_random_modulus(n as u64);
    let r=FiniteField::generate_with_modulus(coeffecients[0].modulus);
    let mut result = coeffecients[0];
    let mut cmul=FiniteField::new(1,coeffecients[0].modulus);
    for i in (1..n).rev() {
        cmul=cmul.mul(&r);
        let other =coeffecients[i].mul(&cmul);
        result =result.add(&other);
    }
    println!("Resulting RS_encoding:\nCoefficients: {:?}\n with Randomness: {} \n Result: {}", coeffecients,r, result);
}
#[test]
fn test_multiplication_large_numbers() {
    let modulus = 17;
    let a = FiniteField::new(u64::MAX - 2, modulus);
    let b = FiniteField::new(u64::MAX - 1, modulus);
    let result = a.mul(&b);
    assert_eq!(
        result.value,
        (((u64::MAX - 2) as u128) * ((u64::MAX - 1) as u128) % (modulus as u128)) as u64
    );
}    