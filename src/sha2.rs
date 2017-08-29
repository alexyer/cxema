use std::clone::Clone;

use digest::{Digest, DigestError, DigestResult, DigestSuccess};

const SHA256_HASH_SIZE: usize = 32;
const BLOCK_SIZE: usize = 64;

// Initial hash value.
const INIT_STATE: [u32; SHA256_HASH_SIZE / 4] = [
    0x6a09e667u32,
    0xbb67ae85u32,
    0x3c6ef372u32,
    0xa54ff53au32,
    0x510e527fu32,
    0x9b05688cu32,
    0x1f83d9abu32,
    0x5be0cd19u32
];

const SHA256_CONSTANTS: [u32; 64] = [
    0x428a2f98u32, 0x71374491u32, 0xb5c0fbcfu32, 0xe9b5dba5u32,
    0x3956c25bu32, 0x59f111f1u32, 0x923f82a4u32, 0xab1c5ed5u32,
    0xd807aa98u32, 0x12835b01u32, 0x243185beu32, 0x550c7dc3u32,
    0x72be5d74u32, 0x80deb1feu32, 0x9bdc06a7u32, 0xc19bf174u32,
    0xe49b69c1u32, 0xefbe4786u32, 0x0fc19dc6u32, 0x240ca1ccu32,
    0x2de92c6fu32, 0x4a7484aau32, 0x5cb0a9dcu32, 0x76f988dau32,
    0x983e5152u32, 0xa831c66du32, 0xb00327c8u32, 0xbf597fc7u32,
    0xc6e00bf3u32, 0xd5a79147u32, 0x06ca6351u32, 0x14292967u32,
    0x27b70a85u32, 0x2e1b2138u32, 0x4d2c6dfcu32, 0x53380d13u32,
    0x650a7354u32, 0x766a0abbu32, 0x81c2c92eu32, 0x92722c85u32,
    0xa2bfe8a1u32, 0xa81a664bu32, 0xc24b8b70u32, 0xc76c51a3u32,
    0xd192e819u32, 0xd6990624u32, 0xf40e3585u32, 0x106aa070u32,
    0x19a4c116u32, 0x1e376c08u32, 0x2748774cu32, 0x34b0bcb5u32,
    0x391c0cb3u32, 0x4ed8aa4au32, 0x5b9cca4fu32, 0x682e6ff3u32,
    0x748f82eeu32, 0x78a5636fu32, 0x84c87814u32, 0x8cc70208u32,
    0x90befffau32, 0xa4506cebu32, 0xbef9a3f7u32, 0xc67178f2u32
];


/**
 *  This structure will hold context information for the SHA-256
 *  hashing operation
 */
#[derive(Copy)]
pub struct Sha256 {
    /// Message Digest
    intermediate_hash: [u32; SHA256_HASH_SIZE / 4],

    /// Message length in bits
    length_low: u32,
    /// Message length in bits
    length_high: u32,

    /// Index into message block array
    message_block_index: i16,

    /// 512-bit message blocks
    message_block: [u8; BLOCK_SIZE],

    /// Is the digest computed?
    computed: bool,
    /// Is the message digest corrupted?
    corrupted: DigestResult
}

impl Clone for Sha256 {
    fn clone(&self) -> Self {
        *self
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        let mut new_sha256 = Sha256 {
            intermediate_hash: [0u32; SHA256_HASH_SIZE / 4],
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0u8; BLOCK_SIZE],
            computed: false,
            corrupted: Ok(DigestSuccess)
        };

        new_sha256.reset();

        new_sha256
    }

    /**
     * This function will process the next 512 bits of the message
     * stored in the message_block array.
     *
     * Many of the variable names in this code, especially the
     * single character names, were used because those were the
     * names used in the publication.
     */
    fn sha256_process_block(&mut self) {
        // Temporary word value
        let mut t1: u32;
        let mut t2: u32;
        let mut w: [u32; 64] = [0; 64];

        for i in 0..16 {
            w[i] = (self.message_block[i * 4] as u32) << 24;
            w[i] |= (self.message_block[i * 4 + 1] as u32) << 16;
            w[i] |= (self.message_block[i * 4 + 2] as u32) << 8;
            w[i] |= self.message_block[i * 4 + 3] as u32;
        }

        for i in 16..64 {
            w[i] = sigma1!(w[i - 2]).wrapping_add(w[i - 7]).wrapping_add(sigma0!(w[i - 15])).wrapping_add(w[i - 16])
        }

        let mut a: u32 = self.intermediate_hash[0];
        let mut b: u32 = self.intermediate_hash[1];
        let mut c: u32 = self.intermediate_hash[2];
        let mut d: u32 = self.intermediate_hash[3];
        let mut e: u32 = self.intermediate_hash[4];
        let mut f: u32 = self.intermediate_hash[5];
        let mut g: u32 = self.intermediate_hash[6];
        let mut h: u32 = self.intermediate_hash[7];

        for i in 0..64 {
            t1 = h.wrapping_add(big_sigma1!(e)).wrapping_add(ch!(e, f, g)).wrapping_add(SHA256_CONSTANTS[i]).wrapping_add(w[i]);
            t2 = big_sigma0!(a).wrapping_add(maj!(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.intermediate_hash[0] = self.intermediate_hash[0].wrapping_add(a);
        self.intermediate_hash[1] = self.intermediate_hash[1].wrapping_add(b);
        self.intermediate_hash[2] = self.intermediate_hash[2].wrapping_add(c);
        self.intermediate_hash[3] = self.intermediate_hash[3].wrapping_add(d);
        self.intermediate_hash[4] = self.intermediate_hash[4].wrapping_add(e);
        self.intermediate_hash[5] = self.intermediate_hash[5].wrapping_add(f);
        self.intermediate_hash[6] = self.intermediate_hash[6].wrapping_add(g);
        self.intermediate_hash[7] = self.intermediate_hash[7].wrapping_add(h);

        self.message_block_index = 0;
    }

    fn sha256_result(&mut self, out: &mut [u8]) {
        assert!(self.corrupted.is_ok());

        if !self.computed {
            self.sha256_pad_message();
            self.message_block = [0; BLOCK_SIZE];
            self.length_high = 0;
            self.length_low = 0;
            self.computed = true;
        }

        for i in 0..SHA256_HASH_SIZE {
            out[i] = (self.intermediate_hash[i >> 2] >> 8 * (3 - (i & 0x03))) as u8;
        }
    }

    fn sha256_pad_message(&mut self) {
        /*
         *  Check to see if the current message block is too small to hold
         *  the initial padding bits and length.  If so, we will pad the
         *  block, process it, and then continue padding into a second
         *  block.
         */
        if self.message_block_index > 55 {
            self.message_block[self.message_block_index as usize] = 0x80;
            self.message_block_index += 1;

            while self.message_block_index < 64 {
                self.message_block[self.message_block_index as usize] = 0;
                self.message_block_index += 1;
            }

            self.sha256_process_block();

            while self.message_block_index < 56 {
                self.message_block[self.message_block_index as usize] = 0;
                self.message_block_index += 1;
            }
        } else {
            self.message_block[self.message_block_index as usize] = 0x80;
            self.message_block_index += 1;

            while self.message_block_index < 56 {
                self.message_block[self.message_block_index as usize] = 0;
                self.message_block_index += 1;
            }
        }

        self.message_block[56] = (self.length_high >> 24) as u8;
        self.message_block[57] = (self.length_high >> 16) as u8;
        self.message_block[58] = (self.length_high >> 8) as u8;
        self.message_block[59] = (self.length_high) as u8;
        self.message_block[60] = (self.length_low >> 24) as u8;
        self.message_block[61] = (self.length_low >> 16) as u8;
        self.message_block[62] = (self.length_low >> 8) as u8;
        self.message_block[63] = (self.length_low) as u8;

        self.sha256_process_block();
    }
}

impl Digest for Sha256 {
    fn reset(&mut self) {
        self.intermediate_hash = INIT_STATE;
        self.length_low = 0;
        self.length_high = 0;
        self.message_block_index = 0;
        self.computed = false;
        self.corrupted = Ok(DigestSuccess);
    }

    fn input(&mut self, input: &[u8]) {
        assert!(!self.computed);
        assert!(self.corrupted.is_ok());

        for i in 0..input.len() {
            self.message_block[self.message_block_index as usize] = input[i];
            self.message_block_index += 1;

            self.length_low = self.length_low.wrapping_add(8);
            if self.length_low == 0 {
                self.length_high = self.length_high.wrapping_add(1);
                if self.length_high == 0 {
                    self.corrupted = Err(DigestError::InputTooLongError);
                }
            }

            if self.message_block_index == 64 {
                self.sha256_process_block();
            }
        }
    }

    fn result(&mut self, out: &mut [u8]) {
        self.sha256_result(out);
    }

    fn output_bits(&self) -> usize { 256 }
    fn block_size(&self) -> usize { BLOCK_SIZE }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Test {
        input: &'static str,
        output_str: &'static str,
    }

    fn test_hash<D: Digest>(sh: &mut D, tests: &[Test]) {
        // Test that it works when accepting the message all at once
        for t in tests.iter() {
            sh.input_str(t.input);

            let out_str = sh.result_str();
            assert!(&out_str[..] == t.output_str);

            sh.reset();
        }

        // Test that it works when accepting the message in pieces
        for t in tests.iter() {
            let len = t.input.len();
            let mut left = len;
            while left > 0 {
                let take = (left + 1) / 2;
                sh.input_str(&t.input[len - left..take + len - left]);
                left = left - take;
            }

            let out_str = sh.result_str();
            assert!(&out_str[..] == t.output_str);

            sh.reset();
        }
    }

    #[test]
    fn test_sha256() {
        // Examples from wikipedia
        let wikipedia_tests = vec![
            Test {
                input: "",
                output_str: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output_str: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"
            },
        ];

        let tests = wikipedia_tests;

        let mut sh = Box::new(Sha256::new());

        test_hash(&mut *sh, &tests[..]);
    }
}