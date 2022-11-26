#![allow(unused_mut)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_upper_case_globals)]
use std::fs;
use polybyte;


const BLOCKSIZE: usize = 128; // Number of bits in block
const Nb: usize = BLOCKSIZE / 32; // Number of columns in state
const Nk: u32 = 4;
const Nr: u32 = 10;

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

fn s_box(b: u8) -> u8 {
    let bin: [u8; 8] = polybyte::byte_to_bin(polybyte::PolyByte::from_byte(b).mult_inv().byte);
    let con: [u8; 8] = polybyte::byte_to_bin(polybyte::PolyByte::from_byte(0x63).byte);
    let mut new_bin: [u8; 8] = [0_u8; 8];

    for i in 0..8 {
        new_bin[8-i-1] = bin[7-i] ^ bin[7-(i+4)%8] ^ bin[7-(i+5)%8] ^ bin[7-(i+6)%8] ^ bin[7-(i+7)%8] ^ con[7-i];
    }
    polybyte::bin_to_byte(new_bin)
}

fn shift_rows(byte_mtrx: &[[u8; 4]; Nb]) -> [[u8; 4]; Nb] {
    let mut new_byte_mtrx: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    for c in 0..Nb {
        for r in 0..4 {
            new_byte_mtrx[c][r] = byte_mtrx[(c+r)%Nb][r];
        }
    }
    new_byte_mtrx
}

fn mix_columns(byte_mtrx: [[u8; 4]; Nb]) -> [[u8; 4]; Nb] {
    let const_poly: [u8; 4] = [0x03, 0x01, 0x01, 0x02];
    let mut tmp_word: polybyte::PolyWord;
    let mut new_byte_mtrx: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    let const_word: polybyte::PolyWord =  polybyte::PolyWord::from_bytes(const_poly);
    
    for c in 0..Nb {
        tmp_word = polybyte::PolyWord::from_bytes(byte_mtrx[c]);
        tmp_word.mult(&const_word);
        new_byte_mtrx[c] = u32::to_be_bytes(tmp_word.word);
    }
    new_byte_mtrx
}

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut new_word: [u8; 4] = [0_u8; 4];
    for i in 0..4 {
        new_word[i] = s_box(w[i]);
    }
    new_word
}

fn rot_word(w: [u8; 4]) -> [u8; 4] {
    let mut new_word: [u8; 4] = [0_u8; 4];
    for i in 0..4 {
        new_word[i] = w[(i+1)%4];
    }
    new_word
}

fn add_round_key(s: &mut [[u8; 4]; Nb], round_key: [u8; 16]) {
    for c in 0..4 {
        for r in 0..4 {
            s[c][r] = s[c][r] ^ round_key[c*4+r];
        }
    }
}

fn key_expansion(key: [u8; 16]) -> [[u8; 4]; Nb*(Nr+1) as usize] {
    let mut key_schedule: [[u8; 4]; Nb*(Nr+1) as usize] = [[0_u8; 4]; Nb*(Nr+1) as usize];
    let mut j: usize;

    for i in 0..Nk {
        j = i as usize;
        key_schedule[j] = [key[j*4], key[j*4+1], key[j*4+2], key[j*4+3]];
    }

    let mut tmp: [u8; 4];
    for i in Nk..(Nb as u32)*(Nr+1) {
        j = i as usize;
        tmp = key_schedule[j-1];
        
        if i % Nk == 0 {
            tmp = sub_word(rot_word(tmp));
            let mut b: polybyte::PolyByte = polybyte::PolyByte::from_byte(0x02);
            b.pow(i/Nk);
            tmp[0] = tmp[0] ^ b.byte;
        } else if Nk > 6 && i%Nk == 4 {
            tmp = sub_word(tmp);
        }
        
        for k in 0..4 {
            key_schedule[j][k] = key_schedule[j-(Nk as usize)][k] ^ tmp[k];
        }
    }
    key_schedule
}

fn cipher(s: &mut [[u8; 4]; Nb],  key_schedule: [u8; 16]) {
    let mut w: [u8; 16] = [0_u8; 16];
    for i in 0..16 {
        w[i] = key_schedule[i];
    }
    
    add_round_key(&mut s, w);
    for i in 1..Nr-1 {
        s = sub_word(s);
        s = shift_rows(s);
        s = mix_columns(s);
        for j in 0..16 {
            w[j] = key_schedule[i*Nb+j];
        }
        add_round_key(&mut s, w);
    }
    s
}

fn main() {
    let path: &str = "/home/nimrafets/projects/rust/tests/aes256/src/main.rs";
    let mut data: Data = Data::from_path(path);
    let key: [u8; 16] = [0x12, 0xff, 0xae, 0xef, 0x11, 0x89, 0x01, 0xc2,
                            0x38, 0xd9, 0x1b, 0xcd, 0xf1, 0x77, 0x8a, 0x88];

    println!("{:?}", &key);
    let key_schedule: [[u8; 4]; Nb*(Nr+1) as usize] = key_expansion(key);
    println!("{:?}", &key_schedule);

    
}
