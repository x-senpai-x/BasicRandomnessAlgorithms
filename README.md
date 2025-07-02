# Basic Randomness Algorithms

A production-grade implementation of cryptographic algorithms from scratch in Rust. This project provides efficient implementations of various cryptographic primitives and protocols commonly used in zero-knowledge proofs and cryptographic applications.

## Project Structure

This project is organized as a Rust workspace with multiple crates, each implementing specific cryptographic functionality:

```
basic-randomness-algorithms/
├── Cargo.toml                 # Workspace configuration
├── README.md                  # This file
├── crates/                    # Core cryptographic crates
│   ├── core/                  # Core utilities and error handling
│   ├── field/                 # Finite field arithmetic
│   ├── polynomial/            # Polynomial arithmetic
│   ├── fft/                   # Fast Fourier Transform
│   ├── fri/                   # FRI (Fast Reed-Solomon Interactive Oracle Proof)
│   ├── sum-check/             # Sum-check protocol
│   ├── rsa/                   # RSA-like operations
│   ├── shamir/                # Shamir's Secret Sharing
│   ├── multilinear/           # Multilinear extensions
│   ├── low-degree-test/       # Low-degree testing
│   └── frievalds/             # Frievalds algorithm
├── examples/                  # Usage examples
├── benches/                   # Performance benchmarks
└── docs/                      # Documentation
```

## Crates Overview

### `crypto-core`
Core cryptographic primitives and utilities:
- Error handling with `thiserror`
- Mathematical utilities (GCD, primality testing, etc.)
- Random number generation utilities

### `crypto-field`
Finite field arithmetic over prime fields:
- Field element operations (add, sub, mul, div, pow)
- Multiplicative group operations
- Boolean hypercube generation
- Random field element generation

### `crypto-polynomial`
Polynomial arithmetic over finite fields:
- Univariate polynomial operations
- Multivariate polynomial operations
- Lagrange interpolation
- Polynomial evaluation

### `crypto-fft`
Fast Fourier Transform implementations:
- FFT over finite fields
- Polynomial multiplication via FFT
- Inverse FFT

### `crypto-fri`
FRI (Fast Reed-Solomon Interactive Oracle Proof):
- Polynomial commitment schemes
- FRI protocol implementation
- Merkle tree constructions

### `crypto-sum-check`
Sum-check protocol implementation:
- Interactive proof system
- Polynomial sum verification
- Round-based protocol execution

### `crypto-rsa`
RSA-like operations:
- Ring arithmetic over composite moduli
- Prime generation
- Modular exponentiation

### `crypto-shamir`
Shamir's Secret Sharing:
- Secret sharing and reconstruction
- Lagrange interpolation for secret recovery
- Threshold-based access control

### `crypto-multilinear`
Multilinear extensions:
- Boolean function extensions
- Evaluation over hypercubes
- Efficient representation

### `crypto-low-degree-test`
Low-degree testing:
- Polynomial degree verification
- Probabilistic testing algorithms
- Soundness and completeness guarantees

### `crypto-frievalds`
Frievalds algorithm:
- Matrix multiplication verification
- Probabilistic correctness checking
- Efficient verification protocols

## Features

- **Production-grade code**: Proper error handling, comprehensive testing, and documentation
- **Rust idioms**: Follows Rust best practices and conventions
- **Modular design**: Each algorithm is implemented as a separate crate
- **Type safety**: Strong type system prevents common cryptographic errors
- **Performance**: Optimized implementations for cryptographic operations
- **Extensibility**: Easy to add new algorithms and protocols

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/basic-randomness-algorithms.git
cd basic-randomness-algorithms
```

2. Build the project:
```bash
cargo build
```

3. Run tests:
```bash
cargo test
```

4. Run benchmarks:
```bash
cargo bench
```

### Usage Examples

#### Finite Field Arithmetic

```rust
use crypto_field::FiniteField;

// Create field elements
let a = FiniteField::new(5, 7)?;
let b = FiniteField::new(3, 7)?;

// Perform arithmetic operations
let sum = a.add(&b)?;
let product = a.mul(&b)?;
let power = a.pow(3)?;

println!("Sum: {}", sum);        // 1 (mod 7)
println!("Product: {}", product); // 1 (mod 7)
println!("Power: {}", power);     // 6 (mod 7)
```

#### Polynomial Operations

```rust
use crypto_polynomial::{Polynomial, Point, interpolate_monomial_basis};
use crypto_field::FiniteField;

// Create interpolation points
let points = vec![
    Point::new(FiniteField::new(0, 7)?, FiniteField::new(1, 7)?)?,
    Point::new(FiniteField::new(1, 7)?, FiniteField::new(2, 7)?)?,
    Point::new(FiniteField::new(2, 7)?, FiniteField::new(4, 7)?)?,
];

// Interpolate polynomial
let poly = interpolate_monomial_basis(&points)?;
println!("Interpolated polynomial: {}", poly);
```

#### Multivariate Polynomials

```rust
use crypto_polynomial::{MultiVariatePolynomial, Term};
use crypto_field::FiniteField;

// Create terms for polynomial: 2x₁²x₂ + x₂x₃
let terms = vec![
    Term::new(FiniteField::new(2, 7)?, vec![2, 1, 0]),
    Term::new(FiniteField::new(1, 7)?, vec![0, 1, 1]),
];

let poly = MultiVariatePolynomial::new(terms, 3)?;

// Evaluate at point (1, 2, 3)
let point = vec![
    FiniteField::new(1, 7)?,
    FiniteField::new(2, 7)?,
    FiniteField::new(3, 7)?,
];

let result = poly.evaluate_point(&point)?;
println!("Evaluation result: {}", result);
```

## Testing

The project includes comprehensive tests for all crates:

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p crypto-field

# Run tests with output
cargo test -- --nocapture
```

## Benchmarks

Performance benchmarks are available for critical operations:

```bash
# Run all benchmarks
cargo bench

# Run benchmarks for a specific crate
cargo bench -p crypto-field
```

## Documentation

Generate and view documentation:

```bash
# Generate documentation
cargo doc

# Open documentation in browser
cargo doc --open
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Rust formatting guidelines (`cargo fmt`)
- Run clippy for linting (`cargo clippy`)
- Ensure all tests pass
- Add documentation for public APIs
- Include examples in documentation

## Security Considerations

⚠️ **Warning**: This is a research and educational implementation. For production use:

- Use established cryptographic libraries (e.g., `ring`, `openssl`)
- Have security audits performed
- Follow cryptographic best practices
- Use appropriate key sizes and parameters

## License

This project is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

- Inspired by various cryptographic protocols and zero-knowledge proof systems
- Built with modern Rust practices and cryptographic best practices
- Designed for educational and research purposes

## References

- [Finite Fields and Their Applications](https://www.cambridge.org/core/books/finite-fields-and-their-applications/)
- [Zero-Knowledge Proofs](https://zkproof.org/)
- [FRI Protocol](https://eprint.iacr.org/2017/573)
- [Sum-Check Protocol](https://eprint.iacr.org/2016/263) 