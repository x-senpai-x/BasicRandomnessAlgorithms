use rs_encoding::prime_field::{FiniteField};
#[derive(Debug,Clone, Copy )]
pub struct Point {
    pub x : FiniteField,
    pub y: FiniteField
}

impl Point{
    pub fn new(x:FiniteField,y:FiniteField)->Point{
        return Point{
            x,y
        };
    }
    pub fn modulus(&self)->u64{
        return self.x.modulus();
    }
}
#[derive(Debug)]
pub struct Polynomial{
    pub coeffecients:Vec<FiniteField> 
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
        return self.coeffecients[0].modulus;
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
//t ordered pairs (x,y) provided to polynomial , and then coeffecients generated  (a1,a2,...at)
//poly evaluated as a1+a2x+a3x2+..atxt-1
pub fn generate_delta (points : &Vec<Point>,modulus : u64 ,t:usize,j : usize,T:FiniteField)->FiniteField{ //delta 1 ,delta 2 , ...delta t 
    //delta_j evaluated at X=T 
    let x_j=points[j as usize].x;
    let mut delta=FiniteField::new(1,modulus);
    for i in 0..t{
        if i==j.try_into().unwrap() {
            continue;
        }
        let x=points[i].x;
        let num = T.sub(&x);
        let den=x_j.sub(&x);
        delta=delta.mul(&num);
        delta=delta.div(&den).unwrap();
    }
    return delta;
}
pub fn evaluate_polynomial (points : &Vec<Point> ,T:FiniteField)->FiniteField{ //delta 1 ,delta 2 , ...delta t 
    //evaluating at a point T
    let t=points.len();
    let modulus=points[0].modulus();
    let mut sum=FiniteField::new(0, modulus);
    for i in 0..t{
        let y=points[i].y;
        let delta=generate_delta(&points, modulus, t, i, T);
        sum=sum.add(&y.mul(&delta));
    }
    return sum;
}

//AI GGenerated --> 
/// Constructs a polynomial in standard monomial basis from interpolation points
pub fn interpolate_monomial_basis(points: &Vec<Point>) -> Polynomial {
    let n = points.len();
    let modulus = points[0].modulus();
    
    // Construct Vandermonde matrix and RHS
    let mut vandermonde = vec![vec![FiniteField::new(0, modulus); n]; n];
    let mut rhs = vec![FiniteField::new(0, modulus); n];

    for i in 0..n {
        let mut power = FiniteField::new(1, modulus);
        for j in 0..n {
            vandermonde[i][j] = power;
            power = power.mul(&points[i].x);
        }
        rhs[i] = points[i].y;
    }

    // Solve V * coeffs = rhs
    let coeffs = solve_linear_system(vandermonde, rhs);
    Polynomial::new(coeffs)
}

/// Solves V * x = y using Gaussian elimination over finite field
fn solve_linear_system(mut matrix: Vec<Vec<FiniteField>>, mut rhs: Vec<FiniteField>) -> Vec<FiniteField> {
    let n = rhs.len();

    // Forward elimination
    for i in 0..n {
        // Find pivot
        let mut pivot = i;
        while pivot < n && matrix[pivot][i].value == 0 {
            pivot += 1;
        }
        assert!(pivot < n, "Singular matrix!");

        matrix.swap(i, pivot);
        rhs.swap(i, pivot);

        // Normalize pivot row
        let inv = matrix[i][i].inverse().unwrap();
        for j in i..n {
            matrix[i][j] = matrix[i][j].mul(&inv);
        }
        rhs[i] = rhs[i].mul(&inv);

        // Eliminate below
        for k in (i + 1)..n {
            let factor = matrix[k][i];
            for j in i..n {
                matrix[k][j] = matrix[k][j].sub(&factor.mul(&matrix[i][j]));
            }
            rhs[k] = rhs[k].sub(&factor.mul(&rhs[i]));
        }
    }

    // Backward substitution
    let mut solution = vec![FiniteField::new(0, matrix[0][0].modulus); n];
    for i in (0..n).rev() {
        let mut sum = FiniteField::new(0, matrix[0][0].modulus);
        for j in (i + 1)..n {
            sum = sum.add(&matrix[i][j].mul(&solution[j]));
        }
        solution[i] = rhs[i].sub(&sum);
    }

    solution
}
