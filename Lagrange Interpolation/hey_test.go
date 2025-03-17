package LagrangeInterpolation

import (
    "math/big"
    "testing"
)

func TestGeneratePrimeField(t *testing.T) {
    n := big.NewInt(10)
    p := generate_prime_field(n)
    if !p.ProbablyPrime(20) {
        t.Errorf("Expected a prime number, got %v", p)
    }
}
func TestGenerateDelta(t *testing.T) {
    points := []*point{
        {big.NewInt(1), big.NewInt(2)},
        {big.NewInt(2), big.NewInt(3)},
        {big.NewInt(3), big.NewInt(4)},
    }
    p := big.NewInt(7)
    x := big.NewInt(5)
    delta := generate_delta(x, points, 1, p)
    expected := big.NewInt(6) // Update this with the correct expected value
    if delta.Cmp(expected) != 0 {
        t.Errorf("Expected %v, got %v", expected, delta)
    }
}
func TestGenerateBasis(t *testing.T) {
    points := []*point{
        {big.NewInt(1), big.NewInt(2)},
        {big.NewInt(2), big.NewInt(3)},
        {big.NewInt(3), big.NewInt(4)},
    }
    p := big.NewInt(7)
    x := big.NewInt(5)
    basis := generate_basis(x, points, p)
    expected := []*big.Int{big.NewInt(3), big.NewInt(6), big.NewInt(6)} // Update these with the correct expected values
    for i, b := range basis {
        if b.Cmp(expected[i]) != 0 {
            t.Errorf("Expected %v, got %v", expected[i], b)
        }
    }
}

func TestGeneratePolynomial(t *testing.T) {
    points := []*point{
        {big.NewInt(1), big.NewInt(2)},
        {big.NewInt(2), big.NewInt(3)},
        {big.NewInt(3), big.NewInt(4)},
    }
    p := big.NewInt(7)
    x := big.NewInt(5)
    polynomial := generate_polynomial(x, points, p)
    expected := big.NewInt(6) // Update this with the correct expected value
    if polynomial.Cmp(expected) != 0 {
        t.Errorf("Expected %v, got %v", expected, polynomial)
    }
}