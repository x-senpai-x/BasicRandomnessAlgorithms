package LagrangeInterpolation 

//Interpolation reconstructs a polynomial from a set of points.
//Given a set of n points (x0, y0), (x1, y1), ..., (xn-1, yn-1), where each xi is unique, the interpolation algorithm reconstructs the polynomial f(x) = y0*a0(x) + y1*a1(x) + y2*a2(x) + ... + yn*an(x) that passes through all the points.
//f(xj)=yj for all j in [0,n-1]
//ai(x)=product of (x-xk)/(xj-xk) for all k in [0,n-1] and k!=j

import (
	"math/big"
	randMath "math/rand"
	"fmt"
)

type point struct {
	x *big.Int
	y *big.Int
}

func generate_prime_field(n *big.Int) *big.Int{
	p:=big.NewInt(0)
	nSquared := new(big.Int).Mul(n, n)
	maxV:=nSquared.Int64()
	//since we want p > max(n**2, m) therefore we will simply add maxV to p
	for !p.ProbablyPrime(20) { //20 tests to check if p is prime i.e Miller-Rabin primality test.
		p=new(big.Int).Add(big.NewInt(maxV),big.NewInt(randMath.Int63()))
	}
	return p
}
func generate_delta(x *big.Int,points []*point,i int,p *big.Int) *big.Int{
	n:=len(points)
	iX:=points[i].x
	numerator:=big.NewInt(1)
	denominator:=big.NewInt(1)
	k:=big.NewInt(0)
	sub:=big.NewInt(0)
	nSub:=big.NewInt(0)
	for j:=0;j<n;j++{
		if i==j{
			continue
		}
		k=points[j].x
		nSub.Mod(new(big.Int).Sub(x,k),p)
		numerator=new(big.Int).Mod(numerator.Mul(numerator,nSub),p)
		sub.Mod(new(big.Int).Sub(iX,k),p)
		denominator=new(big.Int).Mod(denominator.Mul(denominator,sub),p)
	}
	denominator.ModInverse(denominator,p)
	return new(big.Int).Mod(new(big.Int).Mul(numerator,denominator),p)
}
func generate_basis(x *big.Int,points []*point,p *big.Int) []*big.Int{
	n:=len(points)
	basis:=make([]*big.Int,n)
	for i:=0;i<n;i++{
		basis[i]=generate_delta(x,points,i,p)
	}
	return basis
}
func generate_polynomial(x *big.Int,points []*point,p *big.Int) *big.Int{
	n:=len(points)
	basis:=generate_basis(x,points,p)
	polynomial:=big.NewInt(0)
	mul:=big.NewInt(0)
	for i:=0;i<n;i++{
		mul=new(big.Int).Mod(mul.Mul(points[i].y,basis[i]),p)
		polynomial=new(big.Int).Mod(polynomial.Add(polynomial,mul),p)
	}
	return polynomial //evaluated at x 
}

func main(){
	points := []*point{
		{big.NewInt(1), big.NewInt(2)},
		{big.NewInt(2), big.NewInt(3)},
		{big.NewInt(3), big.NewInt(4)},
	}
	p := big.NewInt(7)
	x := big.NewInt(5)
	polynomial := generate_polynomial(x, points, p)
	expected := big.NewInt(6) // This is a placeholder, replace with the correct expected value
	if polynomial.Cmp(expected) != 0 {
		fmt.Printf("Expected %v, got %v", expected, polynomial)
	}
}