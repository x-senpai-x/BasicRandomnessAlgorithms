package main

//Frievalds Algorithm
//Given three n x n boolean matrices A, B, and C, the Frievalds algorithm determines whether C = A * B.
//The algorithm works by sampling the product of A and B and comparing it to C.
//If the product is equal to C, the algorithm returns true; otherwise, it returns false.
//The algorithm is probabilistic and has a small probability of error.
//The algorithm works as follows:
//1. Choose a random n x 1 boolean matrix x.
//2. Compute the product of A and (Br).
//3. Compute the product of C and r.
//4. Compare the two products.

import (
	randMath "math/rand"
	"crypto/rand"
	"fmt"
	"math/big"
)
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
func generate_random_number( p *big.Int ) *big.Int{
	l,err:=rand.Int(rand.Reader,p) // random number between 0 and p
	if err!=nil{
		fmt.Println("Error in generating random number")
	}
	for l == new(big.Int).SetInt64(0){
		l,err = rand.Int(rand.Reader,p)
	}
	return l
}
func generate_row_matrix(n int,r *big.Int,p *big.Int) []*big.Int{
	x:=make([]*big.Int,n)
	for i:=0;i<n;i++{
		x[i]=new(big.Int).SetInt64(0)
		x[i].Exp(r,big.NewInt(int64(i)),p)
	}
	return x
}
func MatrixVectorMultiply(A[][] *big.Int, x []*big.Int, n int, p *big.Int) []*big.Int{
	result:=make([]*big.Int,n)
	mul:=new(big.Int).SetInt64(0)
	for i:=0;i<n;i++{
		result[i]=new(big.Int).SetInt64(0)
		for j:=0;j<n;j++{
			mul.Mod(mul.Mul(A[i][j],x[j]),p)
			result[i].Mod(result[i].Add(result[i],mul),p)
		}
	}
	return result
}
func main (){
	nInt:=5;
	n:=big.NewInt(int64(nInt))
	p:=generate_prime_field(n)
	r:=generate_random_number(p)
	
	A := [][]*big.Int{
		{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)},
		{big.NewInt(6), big.NewInt(7), big.NewInt(8), big.NewInt(9), big.NewInt(10)},
		{big.NewInt(11), big.NewInt(12), big.NewInt(13), big.NewInt(14), big.NewInt(15)},
		{big.NewInt(16), big.NewInt(17), big.NewInt(18), big.NewInt(19), big.NewInt(20)},
		{big.NewInt(21), big.NewInt(22), big.NewInt(23), big.NewInt(24), big.NewInt(25)},
	}

	B := [][]*big.Int{
		{big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		{big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0)},
		{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)},
	}

	C := [][]*big.Int{
		{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)},
		{big.NewInt(6), big.NewInt(7), big.NewInt(8), big.NewInt(9), big.NewInt(10)},
		{big.NewInt(11), big.NewInt(12), big.NewInt(13), big.NewInt(14), big.NewInt(15)},
		{big.NewInt(16), big.NewInt(17), big.NewInt(18), big.NewInt(19), big.NewInt(20)},
		{big.NewInt(21), big.NewInt(22), big.NewInt(23), big.NewInt(24), big.NewInt(25)},
	}


	x:=generate_row_matrix(int(n.Int64()),r,p)
	Br:=MatrixVectorMultiply(B,x,int(n.Int64()),p)
	Cr:=MatrixVectorMultiply(C,x,int(n.Int64()),p)
	AB:=MatrixVectorMultiply(A,Br,int(n.Int64()),p)
		fmt.Println(AB)
		fmt.Println(Cr)

	//just checking for any 1 row 
	
	}
