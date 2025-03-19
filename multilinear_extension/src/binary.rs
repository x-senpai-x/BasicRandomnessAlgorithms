pub fn dec_to_bin(a: u32, v: usize) -> Vec<u8> {
    let mut num = a; // Copy of the input number
    let mut bin = Vec::new(); // Vector to store binary digits

    // Convert decimal to binary
    while num != 0 {
        let rem = (num % 2) as u8; // Get the remainder (0 or 1) and cast to u8
        bin.push(rem); // Push the remainder to the vector
        num /= 2; // Divide the number by 2
    }

    // Pad with leading zeros if necessary
    while bin.len() < v {
        bin.push(0); // Add leading zeros
    }

    bin.reverse(); // Reverse the vector to get the correct order
    bin // Return the binary representation
}