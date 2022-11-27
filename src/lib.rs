#![allow(unused_mut)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_upper_case_globals)]

use std::fs;
use polybyte;
use rand::Rng;
use std::fs::File;
use std::io::Write;


const KEYSIZE: usize = 128;         // Number of bits in cipher key
const BLOCKSIZE: usize = 128;       // Number of bits in block
const BPB: usize = BLOCKSIZE / 8;   // Bytes per block

const Nb: usize = BLOCKSIZE / 32;   // Number of columns in state
const Nk: usize = KEYSIZE / 32;     // Number of 32-bit words in cipher key
const Nr: usize = 10;               // Number of rounds. KEYSIZE=128:Nr=10; 
                                    // KEYSIZE=192:Nr=12; KEYSIZE=256:Nr=14

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        return a;
    } else {
        return gcd(b, a%b);
    }    
}

fn lcm(a: usize, b: usize) -> usize {
    (a / gcd(a, b)) * b        
}

#[derive(Debug)]
pub struct Data {
    bytes: Vec<u8>,
    blocks: Vec<[u8; BPB]>,
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
        let pad_len: usize = lcm(bytes.len(), BPB) - bytes.len();
        bytes.extend(vec![0_u8; pad_len]);

        let mut tmp_block = [0_u8; BPB];
        let mut blocks: Vec<[u8; BPB]> = Vec::new();
        let num_blocks: usize = bytes.len() / BPB;
        for i in 0..num_blocks {
            for j in 0..BPB { 
                tmp_block[j] = bytes[BPB*i+j]; 
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

    pub fn to_file(&mut self, path: &str) {
        let mut bytes: Vec<u8> = Vec::new();
        for byte_mtrx in &self.state {
            for c in 0..Nb {
                for r in 0..4 {
                    bytes.push(byte_mtrx[c][r]);
                }
            }
        }

        let mut buffer = match File::create(path) {
            Ok(b) => b,
            Err(_e) => panic!("Error. Could not create file {}", path),                    
        };
        buffer.write_all(&bytes[..]).unwrap();  
    }
}

fn s_box(b: u8) -> u8 {
    let bin: [u8; 8] = polybyte::byte_to_bin(polybyte::PolyByte::from_byte(b).mult_inv().byte);
    let con: [u8; 8] = polybyte::byte_to_bin(polybyte::PolyByte::from_byte(0x63).byte);
    let mut new_bin: [u8; 8] = [0_u8; 8];

    for i in 0..8 {
        new_bin[8-i-1] = bin[7-i] ^ bin[7-(i+4)%8] ^ bin[7-(i+5)%8] 
                        ^ bin[7-(i+6)%8] ^ bin[7-(i+7)%8] ^ con[7-i];
    }
    polybyte::bin_to_byte(new_bin)
}

fn sub_bytes(byte_mtrx: &mut [[u8; 4]; Nb]) {
    for c in 0..Nb {
        for r in 0..4 {
            byte_mtrx[c][r] = s_box(byte_mtrx[c][r]);
        }
    }
}

fn shift_rows(byte_mtrx: &mut [[u8; 4]; Nb]) {
    let mut new_byte_mtrx: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    for c in 0..Nb {
        for r in 0..4 {
            new_byte_mtrx[c][r] = byte_mtrx[(c+r)%Nb][r];
        }
    }
    *byte_mtrx = new_byte_mtrx;
}

fn mix_columns(byte_mtrx: &mut [[u8; 4]; Nb]) {
    let const_poly: [u8; 4] = [0x03, 0x01, 0x01, 0x02];
    let mut tmp_word: polybyte::PolyWord;
    let mut new_byte_mtrx: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    let const_word: polybyte::PolyWord =  polybyte::PolyWord::from_bytes(const_poly);
    
    for c in 0..Nb {
        tmp_word = polybyte::PolyWord::from_bytes(byte_mtrx[c]);
        tmp_word.mult(&const_word);
        new_byte_mtrx[c] = u32::to_be_bytes(tmp_word.word);
    }
    *byte_mtrx = new_byte_mtrx;
}

fn add_round_key(s: &mut [[u8; 4]; Nb], round_key: [[u8; 4]; Nb]) {
    for c in 0..Nb {
        for r in 0..4 {
            s[c][r] = s[c][r] ^ round_key[c][r];
        }
    }
}

fn cipher(byte_mtrx: &mut [[u8; 4]; Nb], key_schedule: [[u8; 4]; Nb*(Nr+1)]) {
    let mut round_key: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    for i in 0..Nb {
        round_key[i] = key_schedule[i];
    }
    add_round_key(byte_mtrx, round_key);
    
    for i in 1..Nr {
        sub_bytes(byte_mtrx);
        shift_rows(byte_mtrx);
        mix_columns(byte_mtrx);

        for j in 0..Nb {
            round_key[j] = key_schedule[i*Nb+j];
        }
        add_round_key(byte_mtrx, round_key);
    }
    
    sub_bytes(byte_mtrx);
    shift_rows(byte_mtrx);
    
    for i in 0..Nb {
        round_key[i] = key_schedule[Nr*Nb+i];
    }
    add_round_key(byte_mtrx, round_key);
}

fn inv_s_box(b: u8) -> u8 {
    let new_b = b ^ 0x63;
    let bin: [u8; 8] = polybyte::byte_to_bin(polybyte::PolyByte::from_byte(new_b).byte);
    let mut new_bin: [u8; 8] = [0_u8; 8];

    for i in 0..8 {
        new_bin[7-i] = bin[7-(i+2)%8] ^ bin[7-(i+5)%8] ^ bin[7-(i+7)%8];
    }
    polybyte::PolyByte::from_byte(polybyte::bin_to_byte(new_bin)).mult_inv().byte
}

fn inv_sub_bytes(byte_mtrx: &mut [[u8; 4]; Nb]) {
    for c in 0..Nb {
        for r in 0..4 {
            byte_mtrx[c][r] = inv_s_box(byte_mtrx[c][r]);
        }
    }
}

fn inv_shift_rows(byte_mtrx: &mut [[u8; 4]; Nb]) {
    let mut new_byte_mtrx: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    for c in 0..Nb {
        for r in 0..4 {
            new_byte_mtrx[c][r] = byte_mtrx[(c+Nb-r)%Nb][r];
        }
    }
    *byte_mtrx = new_byte_mtrx;
}

fn inv_mix_columns(byte_mtrx: &mut [[u8; 4]; Nb]) {
    let const_poly: [u8; 4] = [0x0b, 0x0d, 0x09, 0x0e];
    let mut tmp_word: polybyte::PolyWord;
    let mut new_byte_mtrx: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    let const_word: polybyte::PolyWord =  polybyte::PolyWord::from_bytes(const_poly);
    
    for c in 0..Nb {
        tmp_word = polybyte::PolyWord::from_bytes(byte_mtrx[c]);
        tmp_word.mult(&const_word);
        new_byte_mtrx[c] = u32::to_be_bytes(tmp_word.word);

        new_byte_mtrx[c] = rot_word(rot_word(new_byte_mtrx[c]));
    }
    *byte_mtrx = new_byte_mtrx;
}

fn inv_cipher(byte_mtrx: &mut [[u8; 4]; Nb], key_schedule: [[u8; 4]; Nb*(Nr+1)]) {
    let mut round_key: [[u8; 4]; Nb] = [[0_u8; 4]; Nb];
    for i in 0..Nb {
        round_key[i] = key_schedule[Nr*Nb+i];
    }
    add_round_key(byte_mtrx, round_key);
    
    for i in (1..Nr).rev() {
        inv_shift_rows(byte_mtrx);
        inv_sub_bytes(byte_mtrx);
        for j in 0..Nb {
            round_key[j] = key_schedule[i*Nb+j];
        }
        add_round_key(byte_mtrx, round_key);
        inv_mix_columns(byte_mtrx);
    }

    inv_shift_rows(byte_mtrx);
    inv_sub_bytes(byte_mtrx);

    for i in 0..Nb {
        round_key[i] = key_schedule[i];
    }
    add_round_key(byte_mtrx, round_key);
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

fn rcon_xor(w: [u8; 4], i: usize) -> [u8; 4] {
    let mut power_byte: polybyte::PolyByte = polybyte::PolyByte::from_byte(0x02);
    power_byte.pow(i as u32);
    let rcon: u32 = u32::from_be_bytes([power_byte.byte, 0x00, 0x00, 0x00]);
    let input_word: u32 = u32::from_be_bytes(w);
    (input_word ^ rcon).to_be_bytes()
}

fn key_expansion(key: [u8; 4*Nk]) -> [[u8; 4]; Nb*(Nr+1)] {
    let mut key_schedule: [[u8; 4]; Nb*(Nr+1)] = [[0_u8; 4]; Nb*(Nr+1)];

    for i in 0..Nk {
        key_schedule[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
    }

    let mut w1: u32;
    let mut w2: u32;
    let mut temp: [u8; 4];
    for i in Nk..Nb*(Nr+1) {
        temp = key_schedule[i-1];
        if i%Nk == 0 {
            temp = rcon_xor(sub_word(rot_word(temp)), i/Nk);
        } else if (Nk > 6) && (i%Nk == 4) {
            temp = sub_word(temp);
        }
        w1 = u32::from_be_bytes(key_schedule[i-Nk]);
        w2 = u32::from_be_bytes(temp);
        key_schedule[i] = (w1 ^ w2).to_be_bytes();
    }
    key_schedule
}

pub fn gen_key(key_path: &str) {
    let key: [u8; 4*Nk] = rand::thread_rng().gen::<[u8; 4*Nk]>();
    let mut buffer = match File::create(key_path) {
        Ok(b) => b,
        Err(_e) => panic!("Error. Could not create file {}", key_path),                    
    };
    buffer.write_all(&key).unwrap();
}

pub fn encrypt(file_path: &str, efile_path: &str, key_path: &str) {
    let mut key: [u8; 4*Nk] = [0_u8; 4*Nk];
    let key_vec: Vec<u8> = fs::read(key_path).expect("Could not read from file");
    for i in 0..4*Nk {
        key[i] = key_vec[i];
    }
    let key_schedule: [[u8; 4]; Nb*(Nr+1)] = key_expansion(key);

    let mut data: Data = Data::from_path(file_path);
    for i in 0..data.state.len() {
        cipher(&mut data.state[i], key_schedule);
    }
    data.to_file(efile_path);
}

pub fn decrypt(file_path: &str, dfile_path: &str, key_path: &str) {
    let mut key: [u8; 4*Nk] = [0_u8; 4*Nk];
    let key_vec: Vec<u8> = fs::read(key_path).expect("Could not read from file");
    for i in 0..4*Nk {
        key[i] = key_vec[i];
    }
    let key_schedule: [[u8; 4]; Nb*(Nr+1)] = key_expansion(key);

    let mut data: Data = Data::from_path(file_path);
    for i in 0..data.state.len() {
        inv_cipher(&mut data.state[i], key_schedule);
    }
    data.to_file(dfile_path);
}

/*
fn main() {
    let key_path: &str = "./key.txt";
    let file_path: &str = "./src/main.rs";
    let efile_path: &str = "./encrypted.txt";
    let dfile_path: &str = "./decrypted.txt";
    gen_key(key_path);
    encrypt(file_path, efile_path, key_path);
    decrypt(efile_path, dfile_path, key_path);
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_expansion() {
        if KEYSIZE == 128 {
            let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x27, 0xae, 0xd2, 0xa6,
                                 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
            let key_schedule: [[u8; 4]; Nb*(Nr+1)] = key_expansion(key);
            assert_eq!(key_schedule[4], [0xa0, 0xfa, 0xfe, 0x17]);
        }
    }
}
