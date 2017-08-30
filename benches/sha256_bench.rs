#![cfg_attr(all(feature = "nightly", test), feature(test))]

#![cfg(all(feature = "nightly", test))]
extern crate test;

extern crate cxema;

#[cfg(test)]
use cxema::sha2::{Sha256};
use cxema::digest::Digest;
use test::Bencher;

#[bench]
pub fn sha256_10(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 10];

    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_1k(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 1024];

    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_64k(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 65536];

    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}