use crate::modulus;
use modulus::{Field, FieldElement};
use crate::rescue_prime::RescuePrime;
use rand::Rng;
use sha2::{Sha512, Digest};
//use ring::hmac;

pub struct LamportPlus {
    field: Field,
    pub pub_acc: [FieldElement; 2], // 公開鍵のアキュムレータ
}

impl LamportPlus {
    const MINE_LIMIT: u64 = 1_000_000; // マイニングのループ回数制限
    const TRACE_LENGTH: usize = 22; // トレースの長さ
    const THRESHOLD_TRACE_LENGTH: usize = 18; // 閾値署名の署名検証トレースの長さ
    const TRACE_STEPS: usize = 1024; // トレースのステップ数
    const STEP_INTERVAL: usize = 8; // ステップの区切り
    const MESSAGE_ACC_RANGE: std::ops::Range<usize> = 0..4; // メッセージのアキュムレータの範囲
    const LEFT_SIGNATURE_ACC_RANGE: std::ops::Range<usize> = 4..10; // 左側の署名のアキュムレータの範囲
    const RIGHT_SIGNATURE_ACC_RANGE: std::ops::Range<usize> = 10..16; // 右側の署名のアキュムレータの範囲
    const PUB_ACC_RANGE: std::ops::Range<usize> = 16..Self::TRACE_LENGTH; // 公開鍵アキュムレータの範囲

    pub fn new() -> Self {
        let field = Field{p: 340282366920938463463374557953744961537}; //(1 << 128) - 45 * (1 << 40) + 1;
        let pub_acc = [Field::zero(field), Field::zero(field)];
        LamportPlus {
            field,
            pub_acc
        }
    }
    pub fn mine_message_sha512(message: &[u8], k: usize) -> Option<(String, u64)> {
        let mut counter = 0u64;

        loop {
            let mut hasher = Sha512::new();
            hasher.update(message);
            hasher.update(counter.to_be_bytes());
            let hash_result = hasher.finalize();

            // ハッシュ結果をビット列に変換
            let bits: String = hash_result
            .iter()
            .map(|byte| format!("{:08b}", byte))
            .collect::<Vec<String>>()
            .concat();


            // 先頭kビットがすべて'0'かチェック kから256ビット目までのビット列を取得
            if bits.starts_with(&"0".repeat(k)) {
                if bits.len() >= k + 256 {
                    return Some((bits[k..k + 256].to_string(), counter));
                } else {
                    return None;
                }
            }

            counter += 1;
            if counter > Self::MINE_LIMIT {
                return None; // 安全のため、ループ回数制限
            }
        }
    }

    // ビット文字列m0, m1
    pub fn keygen(&mut self, mined_bits: &String) -> (Vec<[FieldElement; 2]>, Vec<[FieldElement; 2]>) {
        let n = mined_bits.len(); // 圧縮されたビット列の長さ
        let mut pr = vec![];
        let mut pb = vec![];
        let mut rng = rand::thread_rng();
        let mut rp = RescuePrime::new();
    
        for _ in 0..n {
            let random_byte1: [u8; 16] = rng.gen();  // 128ビット乱数
            let random_byte2: [u8; 16] = rng.gen();  // 128ビット乱数
            let random_bit1 = FieldElement::new(u128::from_be_bytes(random_byte1), self.field);
            let random_bit2 = FieldElement::new(u128::from_be_bytes(random_byte2), self.field);
    
            pr.push([random_bit1, random_bit2]);
            let input = [
                random_bit1,
                random_bit2,
                self.field.zero(),
                self.field.zero(),
            ];
            pb.push(rp.hash(input));
        }
    
        let mut pub_acc = [Field::zero(self.field), Field::zero(self.field)]; 
        // 公開鍵アキュムレータの更新
        for i in 0..n / 2 {
            let left = &pb[n/2 - i - 1];  // ビッグエンディアンなので逆順に処理
            let right = &pb[n - i - 1];    // ビッグエンディアンなので逆順に処理
        
            let acc: [FieldElement; 4] = [
                left[0],
                left[1],
                right[0],
                right[1],
            ];
        
            pub_acc = rp.update(acc);
        }
        self.pub_acc = pub_acc;
    
        (pr, pb)
    }
    
    pub fn sign(&self, mined_bits: &String, pr: &Vec<[FieldElement; 2]>) -> Vec<[FieldElement; 2]> {
        let mut sig = vec![];
        let n = mined_bits.len();
        let half = n / 2;
        let rp = RescuePrime::new();
        let bits: Vec<char> = mined_bits.chars().collect();

    
        // 前半のビットに対する署名 ビッグエンディアンのため後ろから処理
        for i in (0..half).rev() {
            let bit = bits[i];
            if bit == '1' {
                sig.push(pr[i].clone());
            } else {
                let padded = [pr[i][0], pr[i][1], self.field.zero(), self.field.zero()];
                sig.push(rp.hash(padded));
            }
        }
        // 後半のビットに対する署名 ビッグエンディアンのため、逆順に処理
        for i in (half..n).rev() {
            let bit = bits[i];
            if bit == '1' {
                sig.push(pr[i].clone());
            } else {
                let padded = [pr[i][0], pr[i][1], self.field.zero(), self.field.zero()];
                sig.push(rp.hash(padded));
            }
        }
        sig
    }

    pub fn verify(
        &self,
        mined_bits: &String,
        sig: &Vec<[FieldElement; 2]>,
        pub_acc: &[FieldElement; 2],
    ) -> bool {
        let n = mined_bits.len();
        assert!(n % 2 == 0, "mined_bits length must be even");
        let half = n / 2;
        let mut rp = RescuePrime::new();
        let mut acc_verify = [Field::zero(self.field); 2];
        let bits: Vec<char> = mined_bits.chars().collect();
        let mut m0_acc = Field::zero(self.field);
        let mut m1_acc = Field::zero(self.field);
        let two = FieldElement::new(2, self.field);

        for i in 0..half {
            let bit0 = bits[half - i - 1]; // ビッグエンディアンなので逆順に処理
            let bit1 = bits[n - i - 1]; // ビッグエンディアンなので逆順に処理

            // m0, m1 のアキュムレータを更新
            // m0_acc += m0[i] * 2^i
            if bit0 == '1' {
                m0_acc = &m0_acc + &two.pow(i as u128);
            }

            if bit1 == '1' {
                m1_acc = &m1_acc + &two.pow(i as u128);
            }

            // ハッシュまたはそのまま使用
            let left_pb: [FieldElement; 2] = match bit0 {
                '1' => {
                    assert_eq!(sig[i].len(), 2);
                    let input: [FieldElement; 4] = [
                        sig[i][0],
                        sig[i][1],
                        self.field.zero(),
                        self.field.zero(),
                    ];
                    rp.hash(input)
                }
                '0' => sig[i].clone(),
                _ => return false,
            };
    
            let right_pb: [FieldElement; 2] = match bit1 {
                '1' => {
                    assert_eq!(sig[i + half].len(), 2);
                    let input: [FieldElement; 4] = [
                        sig[i + half][0],
                        sig[i + half][1],
                        self.field.zero(),
                        self.field.zero(),
                    ];
                    rp.hash(input)
                }
                '0' => sig[i + half].clone(),
                _ => return false,
            };
    
            // update に渡す配列を [FieldElement; 4] に整形
            assert_eq!(left_pb.len(), 2);
            assert_eq!(right_pb.len(), 2);
            let acc_input: [FieldElement; 4] = [
                left_pb[0],
                left_pb[1],
                right_pb[0],
                right_pb[1],
            ];
            acc_verify = rp.update(acc_input);
        }
        // m0_acc, m1_acc は本当に message の値と一致しているか
        let msg0 = FieldElement::from_bits(&bits[0..half], self.field);  
        let msg1 = FieldElement::from_bits(&bits[half..], self.field); 

        (m0_acc == msg0) && (m1_acc == msg1) && (pub_acc == &acc_verify)
    }

    // トレースを生成しながら検証 Aggregate Trace
    pub fn verify_with_trace_agg(
        &self, 
        mined_bits: &String, 
        sig: &Vec<[FieldElement; 2]>, 
        pub_acc: &[FieldElement; 2]
    ) -> (bool, Vec<[FieldElement; Self::TRACE_LENGTH]>) {
        let n = mined_bits.len();
        assert!(n % 2 == 0, "mined_bits length must be even");
        let half = n / 2;

        let mut rp = RescuePrime::new();
        let mut acc_verify = [Field::zero(self.field); 2];  // 公開鍵アキュムレータの検証用
        // トレースの初期化
        let mut full_trace = vec![[Field::zero(self.field); Self::TRACE_LENGTH]; Self::TRACE_STEPS];


        let bits: Vec<char> = mined_bits.chars().collect();
        let mut m0_acc = Field::zero(self.field);
        let mut m1_acc = Field::zero(self.field);
        let two = FieldElement::new(2, self.field); // 2のフィールド要素

        for i in 0..half {
            let bit0 = bits[half - i - 1]; // ビッグエンディアンなので逆順に処理
            let bit1 = bits[n - i - 1]; // ビッグエンディアンなので逆順に処理
            // 8ステップごとのトレーストレース
            let mut step_trace  = [[Field::zero(self.field); Self::TRACE_LENGTH]; Self::STEP_INTERVAL]; 
            let now_step = i * Self::STEP_INTERVAL;

            // m0, m1 のアキュムレータを更新 iステップ目の1行目 r_0..r_3
            step_trace[0][Self::MESSAGE_ACC_RANGE].copy_from_slice(&[
                m0_acc, m1_acc, self.field.zero(), self.field.zero()
            ]);
            let msg_acc = [
            m0_acc,
            m1_acc,
            match bit0 {
                '1' => Field::one(self.field),
                '0' => Field::zero(self.field),
                _ => panic!("Invalid bit"),
            },
            match bit1 {
                '1' => Field::one(self.field),
                '0' => Field::zero(self.field),
                _ => panic!("Invalid bit"),
            },
            ];
            // メッセージのアキュムレータを更新 8thステップごとに更新 iステップの8行目 r_0..r_3
            step_trace[Self::STEP_INTERVAL-1][Self::MESSAGE_ACC_RANGE]
                .copy_from_slice(&msg_acc);

            // 各ビット処理 & 累積
            if bit0 == '1' {
                m0_acc = &m0_acc + &two.pow(i as u128);
            }
            if bit1 == '1' {
                m1_acc = &m1_acc + &two.pow(i as u128);
            }
            print!("ステップ数: {}, トレース: {:?}, ", i, step_trace);
            // 署名の検証とトレースの更新
            let left_pb = match bit0 {
                '1' => {
                    let input = [sig[i][0], sig[i][1], self.field.zero(), self.field.zero()];
                    let (trace, out) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][Self::LEFT_SIGNATURE_ACC_RANGE].copy_from_slice(&trace[j]);
                    }
                    out
                }
                '0' => {
                    let input = [self.field.zero(); 4];
                    let (trace, _) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][Self::LEFT_SIGNATURE_ACC_RANGE].copy_from_slice(&trace[j]);
                    }
                    [sig[i][0], sig[i][1]] // 署名のハッシュではなくそのまま使用
                }
                _ => return (false, vec![[Field::zero(self.field); Self::TRACE_LENGTH]; Self::TRACE_STEPS]),
            };

            let right_pb = match bit1 {
                '1' => {
                    let input = [sig[i + half][0], sig[i + half][1], self.field.zero(), self.field.zero()];
                    let (trace, out) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][Self::RIGHT_SIGNATURE_ACC_RANGE].copy_from_slice(&trace[j]);
                    }
                    out
                }
                '0' => {
                    let input = [self.field.zero(); 4];
                    let (trace, _) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][Self::LEFT_SIGNATURE_ACC_RANGE].copy_from_slice(&trace[j]);
                    }
                    [sig[i + half][0], sig[i + half][1]] // 署名のハッシュではなくそのまま使用
                }
                _ => return (false, vec![[Field::zero(self.field); Self::TRACE_LENGTH]; Self::TRACE_STEPS]),
            };

            // 公開鍵のアキュムレータ r_16..r_21 の更新
            let acc_input = [left_pb[0], left_pb[1], right_pb[0], right_pb[1]];
            let (trace, acc) = rp.update_with_trace(acc_input);
            for j in 0..Self::STEP_INTERVAL {
                step_trace[j][Self::PUB_ACC_RANGE].copy_from_slice(&trace[j]);
            }
            // トレース更新
            full_trace[now_step..now_step+8].copy_from_slice(&step_trace);
            
            acc_verify = acc;
        }
        (pub_acc == &acc_verify , full_trace)
    }

    // トレースを生成しながら検証 Threshold Trace
    pub fn verify_with_trace_threshold(
        &self, 
        mined_bits: &String, 
        sig: &Vec<[FieldElement; 2]>, 
        pub_acc: &[FieldElement; 2]
    ) -> (bool, Vec<[FieldElement; Self::THRESHOLD_TRACE_LENGTH]>) {
        let n = mined_bits.len();
        assert!(n % 2 == 0, "mined_bits length must be even");
        let half = n / 2;

        let mut rp = RescuePrime::new();
        let mut acc_verify = [Field::zero(self.field); 2];  // 公開鍵アキュムレータの検証用
        // トレースの初期化
        let mut full_trace = vec![[Field::zero(self.field); 18]; Self::TRACE_STEPS];


        let bits: Vec<char> = mined_bits.chars().collect();

        for i in 0..half {
            let bit0 = bits[half - i - 1]; // ビッグエンディアンなので逆順に処理
            let bit1 = bits[n - i - 1]; // ビッグエンディアンなので逆順に処理
            // 8ステップごとのトレーストレース
            let mut step_trace  = [[Field::zero(self.field); Self::THRESHOLD_TRACE_LENGTH]; Self::STEP_INTERVAL]; 
            let now_step = i * Self::STEP_INTERVAL;

            // 署名の検証とトレースの更新
            let left_pb = match bit0 {
                '1' => {
                    let input = [sig[i][0], sig[i][1], self.field.zero(), self.field.zero()];
                    let (trace, out) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][0..6].copy_from_slice(&trace[j]);
                    }
                    out
                }
                '0' => {
                    let input = [self.field.zero(); 4];
                    let (trace, _) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][0..6].copy_from_slice(&trace[j]);
                    }
                    [sig[i][0], sig[i][1]] // 署名のハッシュではなくそのまま使用
                }
                _ => return (false, vec![[Field::zero(self.field); Self::THRESHOLD_TRACE_LENGTH]; Self::TRACE_STEPS]),
            };

            let right_pb = match bit1 {
                '1' => {
                    let input = [sig[i + half][0], sig[i + half][1], self.field.zero(), self.field.zero()];
                    let (trace, out) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][6..12].copy_from_slice(&trace[j]);
                    }
                    out
                }
                '0' => {
                    let input = [self.field.zero(); 4];
                    let (trace, _) = rp.hash_with_trace(input); // trace: Vec<[FieldElement; 6]>
                    for j in 0..Self::STEP_INTERVAL {
                        step_trace[j][6..12].copy_from_slice(&trace[j]);
                    }
                    [sig[i + half][0], sig[i + half][1]] // 署名のハッシュではなくそのまま使用
                }
                _ => return (false, vec![[Field::zero(self.field); Self::THRESHOLD_TRACE_LENGTH]; Self::TRACE_STEPS]),
            };

            // 公開鍵のアキュムレータ r_11..r_17 の更新
            let acc_input = [left_pb[0], left_pb[1], right_pb[0], right_pb[1]];
            let (trace, acc) = rp.update_with_trace(acc_input);
            for j in 0..Self::STEP_INTERVAL {
                step_trace[j][11..17].copy_from_slice(&trace[j]);
            }
            // トレース更新
            full_trace[now_step..now_step+8].copy_from_slice(&step_trace);
            
            acc_verify = acc;
        }
        (pub_acc == &acc_verify , full_trace)
    }
}

pub fn split_and_parse_bits(bits: &str) -> Result<(u128, u128), String> {
    let len = bits.len();
    if len % 2 != 0 {
        return Err("bit string length must be even".to_string());
    }

    let half = len / 2;
    let (left, right) = bits.split_at(half);

    let left_val = u128::from_str_radix(left, 2)
        .map_err(|_| "Failed to parse left half as binary".to_string())?;
    let right_val = u128::from_str_radix(right, 2)
        .map_err(|_| "Failed to parse right half as binary".to_string())?;

    Ok((left_val, right_val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mine_message_finds_solution() {
        let lamport = LamportPlus::new();
        let message = b"test";
        let k = 5; // 先頭5ビットが'0'であることを要求

        let result = LamportPlus::mine_message_sha512(message, k);
        assert!(result.is_some(), "mine_message should return Some(...)");

        let (mined_bits, counter) = result.unwrap();
        assert!(!mined_bits.starts_with("00000"), "mined_bits should start with '0000'");
        assert_eq!(mined_bits.len(), 256);
        assert!(counter <= LamportPlus::MINE_LIMIT);
    }
    //#[test]
    fn test_keygen() {
        let mut lamport = LamportPlus::new();
        // 256ビットのランダムなビット列を生成
        let message = b"test";
        let k = 5; // 先頭5ビットが'0'であることを要求

        let result = LamportPlus::mine_message_sha512(message, k);
        assert!(result.is_some(), "mine_message should return Some(...)");

        let (mined_bits, counter) = result.unwrap();

        let (pr, pb) = lamport.keygen(&mined_bits);
        
        assert_eq!(pr.len(), mined_bits.len());
        assert_eq!(pb.len(), mined_bits.len());
        assert_eq!(pb[0].len(), 2);
    }
    // #[test]
    fn test_sign_and_verify() {
        let mut lamport = LamportPlus::new();
        // 256ビットのランダムなビット列を生成
        let message = b"test";
        let k = 5; // 先頭5ビットが'0'であることを要求

        let result = LamportPlus::mine_message_sha512(message, k);
        assert!(result.is_some(), "mine_message should return Some(...)");

        let (mined_bits, counter) = result.unwrap();

        let (pr, pb) = lamport.keygen(&mined_bits);
        
        let sig = lamport.sign(&mined_bits, &pr);
        
        assert_eq!(sig.len(), mined_bits.len());

        let is_valid = lamport.verify(&mined_bits, &sig, &lamport.pub_acc);
        assert!(is_valid, "Signature should be valid");
    }
    // #[test]
    fn test_verify_with_trace() {
        let mut lamport = LamportPlus::new();
        // 256ビットのランダムなビット列を生成
        let message = b"test";
        let k = 5; // 先頭5ビットが'0'であることを要求

        let result = LamportPlus::mine_message_sha512(message, k);
        assert!(result.is_some(), "mine_message should return Some(...)");

        let (mined_bits, counter) = result.unwrap();

        let (pr, pb) = lamport.keygen(&mined_bits);
        
        let sig = lamport.sign(&mined_bits, &pr);
        
        assert_eq!(sig.len(), mined_bits.len());

        let (is_valid, trace) = lamport.verify_with_trace_agg(&mined_bits, &sig, &lamport.pub_acc);
        assert!(is_valid, "Signature should be valid");
        assert_eq!(trace.len(), LamportPlus::TRACE_STEPS);
    }
}
