use rs_encoding::prime_field::{FiniteField,generate_random_prime_modulus};
mod binary;
use binary::dec_to_bin;
fn main() {
    let v = 3; // f(0,0,0), f(0,0,1), ..., (8 values of f(x)), we create an MLE for it 
    let mut f: Vec<FiniteField> = Vec::with_capacity(2usize.pow(v)); // Corrected power calculation
    let modulus=generate_random_prime_modulus();
    let range_end = 2usize.pow(v as u32) - 1;
    for _ in 0..=range_end {//includes the last value
        f.push(FiniteField::generate_with_modulus(modulus));
    }
    println!("{:?}",f);
    let a: usize=3 ;//MLE value for 4 i.e 1,0,0
    let mut f_mle=FiniteField::new(0,modulus);
    let v_new=v as usize;
    for i in 0..=range_end {
        let x= dec_to_bin(a.try_into().unwrap(),v_new);
        let w=dec_to_bin(i.try_into().unwrap(),v_new);
        let mut chi: u8 =1;
        for j in 0..v_new{
            chi*= (x[j]*w[j]+(1-x[j])*(1-w[j]));
        }
        let temp=&f[i].bin_mul(&chi);
        println!("temp {} {}",i,temp);
        f_mle=f_mle.add (temp);
    }
    println!("{:?}",f_mle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dec_to_bin() {
        assert_eq!(dec_to_bin(0), vec![0]);
        assert_eq!(dec_to_bin(1), vec![1]);
        assert_eq!(dec_to_bin(2), vec![1, 0]);
        assert_eq!(dec_to_bin(5), vec![1, 0, 1]);
        assert_eq!(dec_to_bin(10), vec![1, 0, 1, 0]);
        assert_eq!(dec_to_bin(255), vec![1, 1, 1, 1, 1, 1, 1, 1]);
    }
    fn prime_field_add(){
        let field1=FiniteField::new(1,5);
        let field2=FiniteField::new(2,5);
        

    }
}