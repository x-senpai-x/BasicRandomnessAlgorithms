mod rings;
use rand::{Rng, rng};
use rs_encoding::{prime_field::generate_random_prime_modulus, utils::extended_gcd};
use rings::{generate_prime_of_bitsize, Ring};
#[derive(Debug,Clone, Copy )]
pub struct RSA {
    pub n : u64,
    pub e : u64,
    pub d : u64,
    pub p : u64,
    pub q : u64,
}
impl RSA {
    fn new ()->RSA{
        let mut p=1;
        let mut q=1;
        while (p==q){
            p=generate_random_prime_modulus();
            q=generate_random_prime_modulus();
        }
        let n=p.overflowing_mul(q).0;
        let phi=(p-1)*(q-1);
        let phi_i128: i128 = phi as i128;
        let mut e: u64 = 2;  // Starting with 2 as it's the smallest possible value
        let mut gcd = (0i128, 0i128, 0i128);  // Initialize with default values
        let mut d = 0i128;
        for i in 1..phi{
            gcd=extended_gcd(i.into(), phi_i128);
            if gcd.0==1 {
                e=i;
                d=(gcd.1+phi_i128)%phi_i128;
                break;
            }
        }
        return RSA{n:n,e:e,d:d.try_into().unwrap(),p:p,q:q};
    }
    fn sign (&self,m: u64)->Ring{
        let mut sigma=Ring::new(m, self.n);
        sigma=sigma.pow(self.d);
        return sigma;
    }
    fn verify(&self,m:u64,sigma : Ring) -> u8{
        let m_2= sigma.pow(self.e);
        if (m==m_2.value){
            return 1;
        }
        else{
            return 0 ;
        }
    }
}
fn main(){
    let rsa=RSA::new();
    println!("{:?}",rsa);
}