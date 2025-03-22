use rs_encoding::prime_field::{FiniteField};
use sum_check_protocol::polynomial::Polynomial;
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
pub fn evaluate_polynomial (points : Vec<Point> ,T:FiniteField)->FiniteField{ //delta 1 ,delta 2 , ...delta t 
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