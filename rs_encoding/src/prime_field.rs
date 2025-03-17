use rand::Rng;
use crate::utils::is_prime;
use std::fmt::Display;
#[derive(Debug,Clone, Copy )]
pub struct FiniteField{
    pub value : u64,
    pub modulus : u64
}
pub fn generate_random_prime_modulus () -> u64 {
    let mut rng= rand::rng();
    let mut prime_modulus = rng.random();
    while !is_prime(prime_modulus){
        prime_modulus = rng.random();
    };
    return prime_modulus;
}
pub fn generate_random_numbers_with_modulus(n: u64, modulus: u64) -> Vec<u64> {
    let mut rng = rand::rng();
    let mut numbers = Vec::with_capacity(n as usize);
    for _ in 0..n {
        numbers.push(rng.random::<u64>() % modulus);
    }
    numbers
}
impl FiniteField {
    pub fn new(value: u64, modulus: u64) -> FiniteField {
        return FiniteField{value: value%modulus, modulus: modulus};
    }
    pub fn add(&self, other: &FiniteField) -> FiniteField {
        return FiniteField::new((self.value + other.value) % self.modulus, self.modulus);
    }
    fn sub(&self, other: &FiniteField) -> FiniteField {
        return FiniteField::new((self.value - other.value) % self.modulus, self.modulus);
    }
    pub fn mul(&self, other: &FiniteField) -> FiniteField {
        let result = (self.value as u128) * (other.value as u128) % (self.modulus as u128);
        return FiniteField::new(result as u64, self.modulus);
    }
    fn div(&self, other: &FiniteField) -> FiniteField {
        return FiniteField::new((self.value / other.value) % self.modulus, self.modulus);
    }
    pub fn pow(self , n : u64)->FiniteField {
        let mut other=self;
        for _ in 0..n-1 { 
            other=other.mul(&self);
        }
        return FiniteField::new(other.value,self.modulus); 
    } 
    pub fn new_with_random_modulus(value: u64) -> FiniteField {
        let modulus = generate_random_prime_modulus();
        return FiniteField::new(value, modulus);
    }
    pub fn generate_with_modulus(modulus: u64)->FiniteField{
        let value=generate_random_numbers_with_modulus(1,modulus)[0];
        return FiniteField::new(value, modulus);
    }
    pub fn generate_vector_with_random_modulus(n:u64 )->Vec<FiniteField>{
        let modulus = generate_random_prime_modulus();
        let values : Vec<u64>=generate_random_numbers_with_modulus(n, modulus);
        let mut vector_field:Vec<FiniteField>=Vec::with_capacity(n as usize);
        for i in values {
            vector_field.push(FiniteField::new(i, modulus));
        }
        return vector_field;
    }
}

impl Display for FiniteField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}  (mod {})", self.value, self.modulus)
    }
}