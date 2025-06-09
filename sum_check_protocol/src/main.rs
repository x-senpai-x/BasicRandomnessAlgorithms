mod polynomial;
mod sum_check;
// mod interaction;
use rs_encoding::prime_field::FiniteField;
use sum_check_protocol::{polynomial::MultiVariatePolynomial,sum_check::sum_check_protocol};
//round0 prover sends the entire sum 
//sum is nothing but a constant commitment
//round1 prover sends a polynomial in X1 i,e sum (g(X1,x2,...xv))
// ...
//roundv-1
//roundV

//Prover sends Polynomial struct 
//Verifier sends randomness (finite field )

fn main() {
    let coeffecient=[FiniteField { value: 2, modulus: 2995984900653343099 }, FiniteField { value: 1, modulus: 2995984900653343099 }, FiniteField { value: 1, modulus: 2995984900653343099 }] ;
    let modulus=2995984900653343099;
    println!("Coeffecients: {:?} ", coeffecient.to_vec());
    // let termsWithDeg=vec![vec![3,1,0],vec![0,0,1],vec![0,1,1]];
    let termsWithDeg=vec![vec![3,0,0],vec![1,0,1],vec![0,1,1]];
    let mvPoly=MultiVariatePolynomial{
        coeffecients: coeffecient.to_vec(),
        termsWithDeg: termsWithDeg,
    };
    let points=vec![FiniteField::new(2, modulus),FiniteField::new(3, modulus),FiniteField::new(6, modulus)];
    let result=mvPoly.evaluate_point(&points);
    println!("Result: {:?}",result);
    let point=FiniteField::boolean_hypercube_ff(3, modulus);
    // println!("Point: {:?}",point)
    // for i in point {
    //     for j in i {
    //         println!("{}",j.value);
    //     }
    // }
    println!("{}",mvPoly.evaluate_sum());
    println!("{:?}",mvPoly.degree_variables());
    sum_check_protocol(&mvPoly);
}
