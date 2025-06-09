use std::vec::Vec;
use rs_encoding::prime_field::FiniteField;
use Lagrange_Interpolation::LagrangeInterpolation::{Point, evaluate_polynomial,Polynomial,interpolate_monomial_basis};
use crate::polynomial::{MultiVariatePolynomial};

pub struct SumCheckRoundMessage {
    pub polynomial: Polynomial,
    pub claimed_sum: FiniteField,
}

pub fn sum_check_protocol(
    poly: &MultiVariatePolynomial,
) -> bool {
    //lets say the polynomial is g(X1, X2, X3) = 2{X_1}^3 + X_1X_3 + X_2X_3
    let modulus = poly.modulus();
    let num_vars = poly.termsWithDeg[0].len();//3
    let mut claimed_sum = poly.evaluate_sum();//initial commitment that needs to be proved/verified
    let mut r: Vec<FiniteField> = vec![];//it will store r1,r2,...rv if there are v terms 
    println!("Initial claimed sum over Boolean hypercube: {:?}", claimed_sum);
    let degrees=poly.degree_variables();
    for round in 0..num_vars {
        // Construct univariate polynomial g_v(X_v) := sum over x_{v+1} to x_n of g(r_1,...,r_{v-1}, X_v, x_{v+1},...,x_n)
        let mut points: Vec<Point> = Vec::new();
        for x in 0..= degrees[round]{
            let mut input: Vec<FiniteField> = r.clone();
            input.push(FiniteField::new(x, modulus));
            // Fill remaining variables with all possible 2^{n - (v+1)} binary values and sum evaluations
            let remaining = num_vars - (round + 1);
            let hypercube = FiniteField::boolean_hypercube_ff(remaining, modulus);
            let mut eval_sum = FiniteField::new(0, modulus);
            for suffix in hypercube.iter() {
                let mut full_input = input.clone();
                full_input.extend_from_slice(suffix);
                let val = poly.evaluate_point(&full_input);
                eval_sum = eval_sum.add(&val);
            }
            points.push(Point::new(FiniteField::new(x, modulus), eval_sum));
        }
        let univariate_poly: Polynomial=interpolate_monomial_basis(&points);//a0,a1,a2,...
        // Verify that g_v(0) + g_v(1) == previous round claimed sum

        let univariate_poly_0 = evaluate_polynomial(&points, FiniteField { value: (0), modulus: (modulus) });
        let univariate_poly_1 = evaluate_polynomial(&points, FiniteField { value: (1), modulus: (modulus) });
        let sum_check = univariate_poly_0.add(&univariate_poly_1);
        if sum_check.value != claimed_sum.value {
            println!("Round {}: Rejected due to incorrect sum: {:?} != {:?}", round, sum_check, claimed_sum);
            return false;
        }
        println!("Round {}: Polynomial sent: {:?}", round, univariate_poly);

        // Verifier chooses a random point r_v and sends it to prover
        let r_v = FiniteField::generate_with_modulus(modulus);
        println!("Round {}: Verifier chooses random r_{} = {:?}", round, round + 1, r_v);
        r.push(r_v);

        // Compute new claimed sum = g_v(r_v) for next round
        claimed_sum = univariate_poly.evaluate(&r_v);
    }

    // Final check
    let eval = poly.evaluate_point(&r);
    if eval.value != claimed_sum.value {
        println!("Final check failed: g({:?}) = {:?} != {:?}", r, eval, claimed_sum);
        return false;
    }
    println!("Sum-check protocol succeeded. Verifier accepts.");
    true
}

// use rs_encoding::prime_field::FiniteField;
// use crate::polynomial::{Polynomial,MultiVariatePolynomial};

// pub fn sum_check_protocol(mvPoly:MultiVariatePolynomial){
//     //Round0 : Prover Sends commitment to Verifier
//     let C=mvPoly.evaluate_sum();
//     //Round1 : Prover sends g1(X1)
//     let degree_variables=mvPoly.degree_variables(); 


// }