use std::cmp::max;
use Lagrange_Interpolation::LagrangeInterpolation::{Point,evaluate_polynomial};
use rs_encoding::prime_field::FiniteField;

#[derive(Debug)]
pub struct MultiVariatePolynomial{
//Say g(X1,X2,X3)= 2{X_1}^3 + X_1X_3 + X_2X_3
//if there are t terms then len(coeff)=t
//if there are n variables then termsWithDeg is a vector of length n and each of the element is iteself a vector of length t each representing the degree contribution in each of the term
    pub coeffecients:Vec<FiniteField>, 
    pub termsWithDeg:Vec<Vec<u64>>
}
impl MultiVariatePolynomial{
    // pub fn evaluate_at_n_random_points(&self,n:u64,T:FiniteField)->FiniteField{
    //     let modulus=self.modulus();
    //     let n_points:Vec<FiniteField>=FiniteField::generate_vector_with_fixed_modulus(n,modulus);
    //     let mut Two_dPoints: Vec<Point>=Vec::new();
    //     for point in n_points{
    //         let y_point=self.evaluate_point(point);
    //         let Two_dPoint=Point::new(point,y_point);
    //         Two_dPoints.push(Two_dPoint);
    //     }
    //     evaluate_polynomial(Two_dPoints, T) //evalutate result at point T
        
    // }
    pub fn evaluate_point(&self, points: &Vec<FiniteField>) -> FiniteField{
        let modulus= self.modulus();
        let nterms= self.coeffecients.len();
        let nvariables= self.termsWithDeg[0].len();
        let mut result=FiniteField::new(0,modulus);
        for term in 0..nterms{ 
            let coeff=self.coeffecients[term];
            let mut mult_result=FiniteField::new(1, modulus);
            for mult_variables in 0..nvariables{
                let imdt= points[mult_variables].pow(self.termsWithDeg[term][mult_variables]);
                mult_result=mult_result.mul(&imdt)
            }
            let mul_result=coeff.mul(&mult_result);
            result=result.add(&mul_result);
        }
        return result;
    }
    pub fn evaluate_sum(&self)->FiniteField{
        let modulus=self.modulus();
        let nterms= self.coeffecients.len();
        let nvariables= self.termsWithDeg[0].len();
        let points_boolean=FiniteField::boolean_hypercube_ff(nvariables, modulus);
        let mut sum=FiniteField::new(0, modulus);
        for point in points_boolean{
            let eval=self.evaluate_point(&point);
            sum=sum.add(&eval);
        }
        return sum; 
    }
    pub fn degree_variables(&self)->Vec<u64>{
        let nterms= self.coeffecients.len();
        let nvariables= self.termsWithDeg[0].len();
        let mut degree_variables: Vec<u64>=vec![0;nvariables] ;
        for term in 0..nterms{
            for mult_variables in 0..nvariables{
                degree_variables[mult_variables]=max(degree_variables[mult_variables], self.termsWithDeg[term][mult_variables])
            }
        }
        return degree_variables;
    }
    pub fn modulus(&self)->u64{
        return self.coeffecients[0].modulus;
    }



}


