use rs_encoding::prime_field::{generate_random_numbers_with_modulus, FiniteField};
use sum_check_protocol::polynomial::Polynomial;
use Lagrange_Interpolation::LagrangeInterpolation::{Point,evaluate_polynomial};
use rand::Rng;

fn main() {
    let t=2;
    let n=5;
    let secret=43 ;//secret value 
    let mut coeffecients=FiniteField::generate_vector_with_random_modulus(t-1);
    let modulus=coeffecients[0].modulus();
    let value=FiniteField::new(secret,modulus);
    coeffecients.insert(0,value);
    println!("Coeffecients {:?}",coeffecients);
    // polynomial evaluated at n points
    let polynomial=Polynomial::new(coeffecients);
    println!("Polynomial {:?}",polynomial);
    let mut shares: Vec<Point>=Vec::new();
    for i in 1..=n{
        let point=FiniteField::new(i, modulus);
        let value=polynomial.evaluate(&point);
        shares.push(Point::new(point,value));
    } 
    println!("Shares , the n points generated with polynomial {:?}",shares);
    // n points generated and distributed 
    // after these shares obtained , t used to obtain the polynomial  and then p(0) gives the secret
    // we use lagrange interpolation to combine them 
    //randomy generate t values from 0 to n-1  which will be used to index and fetch the t points
    let points=generate_unique_random_indices(n, t.try_into().unwrap());
    println!("Randomindices {:?}",points );
    let mut t_shares: Vec<Point>=Vec::new();
    for i in 0..t.try_into().unwrap(){
        let iterator=points[i];
        let sh=shares[iterator as usize];
        t_shares.push(sh);
    }
    println!("t tshares are {:?}",t_shares);
    // t_shares stores all the t points that will be interpolated to form polynomial
    // the polynomial when evaluated at point 0 will give us the Secret
    let Tsecret=evaluate_polynomial(t_shares, FiniteField::new(0, modulus));
    println!("Secret {}", Tsecret);
}

fn generate_unique_random_indices(max: u64, count: usize) -> Vec<u64> {
    let mut rng = rand::thread_rng();
    let mut indices = Vec::new();
    
    while indices.len() < count {
        let random_index = rng.gen_range(0..max);
        if !indices.contains(&random_index) {
            indices.push(random_index);
        }
    }
    
    indices
}