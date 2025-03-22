use rs_encoding::prime_field::FiniteField;
#[derive(Debug)]
pub struct Polynomial{
    coeffecients:Vec<FiniteField> 
}
impl Polynomial {
    pub fn new(coeffecients: Vec<FiniteField>)->Polynomial{
        // Coefficients in ascending order of degree: a_0 + a_1*x + a_2*x^2 + ...

        return Polynomial{coeffecients: coeffecients};
    }   
    fn len (&self)->usize{
        return self.coeffecients.len()
    }
    fn degree (&self)->usize{
        return  self.len()-1;
    }
    pub fn modulus(&self)->u64{
        return self.coeffecients[0].modulus();
    }
    pub fn evaluate(&self,point : &FiniteField)->FiniteField{//point is a binary input
        let mut result:FiniteField= self.coeffecients[0];
        for i in 1..self.len(){
            let pow=point.pow(i as u64);
            result=result.add(&self.coeffecients[i].mul(&pow));
        }
        return result;
    }   
}

