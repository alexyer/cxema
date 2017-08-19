use std::clone::Clone;

use digest::{Digest, DigestError, DigestResult, DigestSuccess};

const SHA1_HASH_SIZE: usize = 20;
const BLOCK_SIZE: usize = 64;

// Initial hash value.
const INIT_STATE: [u32; SHA1_HASH_SIZE / 4] = [
    0x67452301u32,
    0xefcdab89u32,
    0x98badcfeu32,
    0x10325476u32,
    0xc3d2e1f0u32
];

/**
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
#[derive(Copy)]
pub struct Sha1 {
    /// Message Digest
    intermediate_hash: [u32; SHA1_HASH_SIZE / 4],

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

impl Clone for Sha1 {
    fn clone(&self) -> Self {
        *self
    }
}

impl Sha1 {
    pub fn new() -> Sha1 {
        let mut new_sha1 = Sha1 {
            intermediate_hash: [0u32; SHA1_HASH_SIZE / 4],
            length_low: 0,
            length_high: 0,
            message_block_index: 0,
            message_block: [0u8; BLOCK_SIZE],
            computed: false,
            corrupted: Ok(DigestSuccess)
        };

        new_sha1.reset();

        new_sha1
    }

    /**
     * This function will process the next 512 bits of the message
     * stored in the Message_Block array.
     *
     * Many of the variable names in this code, especially the
     * single character names, were used because those were the
     * names used in the publication.
     */
    fn sha1_process_block(&mut self) {
        // Temporary word value
        let mut temp: u32;
        let mut w: [u32; 80] = [0; 80];

        for i in 0..16 {
            w[i] = (self.message_block[i * 4] as u32) << 24;
            w[i] |= (self.message_block[i * 4 + 1] as u32) << 16;
            w[i] |= (self.message_block[i * 4 + 2] as u32) << 8;
            w[i] |= self.message_block[i * 4 + 3] as u32;
        }

        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a: u32 = self.intermediate_hash[0];
        let mut b: u32 = self.intermediate_hash[1];
        let mut c: u32 = self.intermediate_hash[2];
        let mut d: u32 = self.intermediate_hash[3];
        let mut e: u32 = self.intermediate_hash[4];

        for i in 0..80 {
            let (k, f) = match i {
                0...19 => (0x5A827999, ch!(b, c, d)),
                20...39 => (0x6ED9EBA1, parity!(b, c, d)),
                40...59 => (0x8F1BBCDC, maj!(b, c, d)),
                60...79 => (0xCA62C1D6, parity!(b, c, d)),
                _ => unreachable!()
            };

            temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;

        }

        self.intermediate_hash[0] = self.intermediate_hash[0].wrapping_add(a);
        self.intermediate_hash[1] = self.intermediate_hash[1].wrapping_add(b);
        self.intermediate_hash[2] = self.intermediate_hash[2].wrapping_add(c);
        self.intermediate_hash[3] = self.intermediate_hash[3].wrapping_add(d);
        self.intermediate_hash[4] = self.intermediate_hash[4].wrapping_add(e);

        self.message_block_index = 0;
    }

    fn sha1_result(&mut self, out: &mut [u8]) {
        assert!(self.corrupted.is_ok());

        if !self.computed {
            self.sha1_pad_message();
            self.message_block = [0; BLOCK_SIZE];
            self.length_high = 0;
            self.length_low = 0;
            self.computed = true;
        }

        for i in 0..SHA1_HASH_SIZE {
            out[i] = (self.intermediate_hash[i >> 2] >> 8 * (3 - (i & 0x03))) as u8;
        }
    }

    fn sha1_pad_message(&mut self) {
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

            self.sha1_process_block();

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

        self.sha1_process_block();
    }
}

impl Digest for Sha1 {
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
                self.sha1_process_block();
            }
        }

    }

    fn result(&mut self, out: &mut [u8]) {
        self.sha1_result(out);
    }

    fn output_bits(&self) -> usize { 160 }
    fn block_size(&self) -> usize { BLOCK_SIZE }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Test {
        input: &'static str,
        output: Vec<u8>,
        output_str: &'static str,
    }

    #[test]
    fn test() {
        let tests = vec![
            Test {
                input: "abc",
                output: vec![
                    0xA9u8, 0x99u8, 0x3Eu8, 0x36u8,
                    0x47u8, 0x06u8, 0x81u8, 0x6Au8,
                    0xBAu8, 0x3Eu8, 0x25u8, 0x71u8,
                    0x78u8, 0x50u8, 0xC2u8, 0x6Cu8,
                    0x9Cu8, 0xD0u8, 0xD8u8, 0x9Du8,
                ],
                output_str: "a9993e364706816aba3e25717850c26c9cd0d89d"
            },
            Test {
                input:
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                output: vec![
                    0x84u8, 0x98u8, 0x3Eu8, 0x44u8,
                    0x1Cu8, 0x3Bu8, 0xD2u8, 0x6Eu8,
                    0xBAu8, 0xAEu8, 0x4Au8, 0xA1u8,
                    0xF9u8, 0x51u8, 0x29u8, 0xE5u8,
                    0xE5u8, 0x46u8, 0x70u8, 0xF1u8,
                ],
                output_str: "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
            },
            // Examples from wikipedia
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output: vec![
                    0x2fu8, 0xd4u8, 0xe1u8, 0xc6u8,
                    0x7au8, 0x2du8, 0x28u8, 0xfcu8,
                    0xedu8, 0x84u8, 0x9eu8, 0xe1u8,
                    0xbbu8, 0x76u8, 0xe7u8, 0x39u8,
                    0x1bu8, 0x93u8, 0xebu8, 0x12u8,
                ],
                output_str: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            },
            Test {
                input: "The quick brown fox jumps over the lazy cog",
                output: vec![
                    0xdeu8, 0x9fu8, 0x2cu8, 0x7fu8,
                    0xd2u8, 0x5eu8, 0x1bu8, 0x3au8,
                    0xfau8, 0xd3u8, 0xe8u8, 0x5au8,
                    0x0bu8, 0xd1u8, 0x7du8, 0x9bu8,
                    0x10u8, 0x0du8, 0xb4u8, 0xb3u8,
                ],
                output_str: "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
            },
        ];

        let mut out = [0u8; 20];

        let mut sh = Box::new(Sha1::new());
        for t in tests.iter() {
            (*sh).input_str(t.input);
            sh.result(&mut out);
            assert!(t.output[..] == out[..]);

            let out_str = (*sh).result_str();
            assert_eq!(out_str.len(), 40);
            assert!(&out_str[..] == t.output_str);

            sh.reset();
        }

        // Test that it works when accepting the message in pieces
        for t in tests.iter() {
            let len = t.input.len();
            let mut left = len;
            while left > 0 {
                let take = (left + 1) / 2;
                (*sh).input_str(&t.input[len - left..take + len - left]);
                left = left - take;
            }
            sh.result(&mut out);
            assert!(t.output[..] == out[..]);

            let out_str = (*sh).result_str();
            assert_eq!(out_str.len(), 40);
            assert!(&out_str[..] == t.output_str);

            sh.reset();
        }
    }
}