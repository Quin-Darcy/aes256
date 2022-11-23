#![allow(unused_mut)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_upper_case_globals)]
use std::fs;
use polybyte;


const BLOCKSIZE: usize = 128; // Number of bits in block
const Nb: usize = BLOCKSIZE / 32; // Number of columns in state

fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        return a;
    } else {
        return gcd(b, a%b);
    }    
}

fn lcm(a: u32, b: u32) -> u32 {
    (a / gcd(a, b)) * b        
}

#[derive(Debug)]
struct Data {
    bytes: Vec<u8>,
    blocks: Vec<[u8; 16]>,
    state: Vec<[[u8; 4]; Nb]>,
}

impl Data {
    pub fn new() -> Self {
        Data {
            bytes: Vec::new(),
            blocks: Vec::new(),
            state: Vec::new(),
        }
    }

    pub fn from_path(path: &str) -> Self {
        let mut bytes: Vec<u8> = fs::read(path).expect("Could not read from file");
        let num_bits: u32 = 8*bytes.len() as u32;
        let pad_len: usize = (((lcm(num_bits, BLOCKSIZE as u32) as usize) - 8*bytes.len()) / 8) as usize;
        bytes.extend(vec![0_u8; pad_len]);

        let mut tmp_block = [0_u8; 16];
        let mut blocks: Vec<[u8; 16]> = Vec::new();
        let num_blocks: usize = bytes.len() / (BLOCKSIZE as usize);
        for i in 0..num_blocks {
            for j in 0..16 { 
                tmp_block[j] = bytes[16*i+j]; 
            }
            blocks.push(tmp_block);
        }

        let mut tmp_col = [0_u8; 4];
        let mut byte_mtrx: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
        let mut state: Vec<[[u8; 4]; Nb]> = Vec::new();
        for i in 0..num_blocks {
            for j in 0..Nb {
                for k in 0..4 {
                    tmp_col[k] = blocks[i][4*j+k];
                }
                byte_mtrx[j] = tmp_col;
            }
            state.push(byte_mtrx);
        }

        Data {
            bytes: bytes,
            blocks: blocks,
            state: state,
        }
    }
}

fn sbox(b: u8) -> u8 {
    let bin: [u8; 8] = polybyte::byte_to_bin(polybyte::PolyByte::from_byte(b).mult_inv().byte);
    let con: [u8; 8] = polybyte::byte_to_bin(polybyte::PolyByte::from_byte(0x63).byte);
    let mut new_bin: [u8; 8] = [0_u8; 8];

    for i in 0..8 {
        new_bin[8-i-1] = bin[7-i] ^ bin[7-(i+4)%8] ^ bin[7-(i+5)%8] ^ bin[7-(i+6)%8] ^ bin[7-(i+7)%8] ^ con[7-i];
    }
    polybyte::bin_to_byte(new_bin)
}

fn main() {
    let path: &str = "/home/nimrafets/projects/rust/tests/aes256/src/main.rs";
    let mut data: Data = Data::from_path(path);
}
