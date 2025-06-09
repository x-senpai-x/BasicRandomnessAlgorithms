mod LagrangeInterpolation;
use LagrangeInterpolation::{Point,interpolate_monomial_basis};
use rs_encoding::prime_field::FiniteField;
fn main() {
    let modu=FiniteField::new_with_random_modulus(0).modulus();
    let point_0=Point::new(FiniteField::new(0,modu),FiniteField::new(3,modu));
    let point_1=Point::new(FiniteField::new(1,modu),FiniteField::new(9,modu));
    let point_2=Point::new(FiniteField::new(2,modu),FiniteField::new(17,modu));
    println!("{:?}",interpolate_monomial_basis(&vec![point_0,point_1,point_2]));
}
