use crate::modulus;
use modulus::Field;
use modulus::FieldElement;
use crate::rescue_prime::RescuePrime;
use rand::Rng;
//use ring::hmac;

pub struct LamportPlus {
    field: Field,
    rp: RescuePrime,
    pub_acc: Vec<FieldElement>, // 公開鍵のアキュムレータ
}

impl LamportPlus {
    pub fn new() -> Self {
        let field = Field{p: 340282366920938463463374557953744961537}; //(1 << 128) - 45 * (1 << 40) + 1;
        let rp = RescuePrime::new();
        let mut pub_acc = vec![];
        LamportPlus {
            field,
            rp,
            pub_acc
        }
    }
    // メッセージビットMをh'に縮小し、分割（ZKP回路外で行うべきらしい）
    pub fn reduce_message(self, m: &str) -> (&str, &str) {
        let counter: u128 = 0; //カウンタC
        ("aa", "bb")
    }

    // ビット文字列m0, m1
    pub fn keygen(&mut self, m0: &str, m1: &str) -> (Vec<Vec<FieldElement>>, Vec<Vec<FieldElement>>) {
        let n = m0.len() + m1.len();
        let mut pr = vec![];
        let mut pb = vec![];

        let mut rng = rand::thread_rng();// スレッドローカルな乱数生成器を取得
    
        // 0から9の範囲の整数を生成
        let random_number: u32 = rng.gen_range(0..10);
    
        for _ in 0..n {
            // 128ビットの乱数を生成
            let random_byte1: [u8; 16] = rng.gen();  // 16バイト = 128ビット
            let random_byte2: [u8; 16] = rng.gen();  // 16バイト = 128ビット
            let random_bit1 = FieldElement::new(u128::from_be_bytes(random_byte1), self.field);
            let random_bit2 = FieldElement::new(u128::from_be_bytes(random_byte2), self.field);
            pr.push(vec![
                random_bit1,
                random_bit2
            ]);
            pb.push(self.rp.hash(vec![random_bit1, random_bit2]));
        }

        // 公開鍵アキュムレータ
        for i in 0..n/2 {
            let mut acc = pb[i].iter().chain(pb[n/2+i].iter()).cloned().collect();
            self.pub_acc = self.rp.update(acc);
        }

        (pr, pb)
    }

    pub fn sign(&self, m0: &str, m1: &str, pr: Vec<Vec<FieldElement>>) -> Vec<Vec<FieldElement>> {
        // pr, pbを計算する
        let mut sig = vec![vec![]];
        let n = m0.len() + m1.len();

        for i in 0..n/2 {
            if check_bits(m0, i) == '1' {
                sig.push(pr[i].clone());
            } else {
                sig.push(self.rp.hash(pr[i].clone()));
            }
            if check_bits(m1, i) == '1' {
                sig.push(pr[i+n/2].clone());
            } else {
                sig.push(self.rp.hash(pr[i+n/2].clone()));
            }
        }
        sig
    }

    pub fn verify(&mut self, m0: &str, m1: &str, pb: Vec<Vec<FieldElement>>, sig: Vec<Vec<FieldElement>>) -> bool {
        let n = m0.len() + m1.len();
        let mut acc_verify = vec![];
        let mut m0_acc: u128 = 0;
        let mut m1_acc: u128 = 0;

        for i in 0..n {
            let mut left_pb = vec![];
            let mut right_pb = vec![];

            if check_bits(m0, i) == '1' {
                left_pb = self.rp.hash(sig[i].clone());
                m0_acc = m0_acc + (1 << i);
            } else {
                left_pb = sig[i].clone();
            }
            if check_bits(m1, i) == '1' {
                m1_acc = m1_acc + (1 << i);
                right_pb = self.rp.hash(sig[i+n/2].clone())
            } else {
                right_pb = sig[i+n/2].clone();
            }
            let mut acc = left_pb.iter().chain(right_pb.iter()).cloned().collect();
            acc_verify = self.rp.update(acc);
        }
        let m0_number = u128::from_str_radix(&m0, 2).expect("Failed to convert");
        let m1_number = u128::from_str_radix(&m1, 2).expect("Failed to convert");
        m0_number == m0_acc && m1_number == m1_acc && self.pub_acc == acc_verify
    }
}

pub fn check_bits(m: &str, index: usize) -> char {
    if let Some(charactor) = m.chars().nth(m.len()-index) {
        charactor
    } else {
        '0'
    }
}