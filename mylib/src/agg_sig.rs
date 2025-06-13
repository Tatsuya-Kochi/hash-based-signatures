use std::collections::{HashMap};
use crate::modulus;
use crate::mpolynomial::MPolynomial;
use crate::proofstream::ProofStream;
use crate::rescue_prime;
use modulus::{Field, FieldElement};
use crate::lamport_plus::LamportPlus;
use crate::lamport_plus::split_and_parse_bits;
use crate::stark::Stark;

pub struct AggSig{
    pub num_signer: usize, // 署名者の数
    pub messages: Vec<Vec<u8>>, // メッセージ
    pub pub_keys: Vec<Vec<[FieldElement; 2]>>, // 公開鍵
    pub pub_accs: Vec<[FieldElement; 2]>, // 公開鍵アキュムレータ
    pub signs: Vec<Vec<[FieldElement; 2]>>, // 署名
    pub field: Field,
    pub expansion_factor: usize,
    pub num_colinearity_checks: usize,
    pub security_level: usize,
    pub num_registers: usize,
    pub num_cycles: usize,
    pub transition_constraints_degree: usize,
    pub stark: Stark, //STARKインスタンス
}

impl AggSig {
    // 署名者の数、メッセージ、公開鍵、署名、トレースは
    pub fn new(
        num_signer: usize,
        messages: Vec<Vec<u8>>,
        pub_keys: Vec<Vec<[FieldElement; 2]>>,
        pub_accs: Vec<[FieldElement; 2]>,
        signs: Vec<Vec<[FieldElement; 2]>>,
        field: Field,
        expansion_factor: usize, // ドメインの拡張
        num_colinearity_checks: usize, // 低次テストのクエリ回数
        security_level: usize,
        num_registers: usize,
        num_cycles: usize,
        transition_constraints_degree: usize,
    ) -> Self {
        let stark = Stark::new(
            field,
            expansion_factor,
            num_colinearity_checks,
            security_level,
            num_registers,
            num_cycles,
            transition_constraints_degree,
        );        
        AggSig { 
            num_signer, 
            messages, 
            pub_keys, 
            pub_accs,
            signs, 
            field,
            expansion_factor,
            num_colinearity_checks,
            security_level,
            num_registers,
            num_cycles,
            transition_constraints_degree,
            stark 
        }         
    }

    // 一つ一つの署名の検証と共にトレースを生成 ここで公開鍵アキュムレータの値を保持しておく必要がある
    pub fn verify_each_sign(&self) -> (bool, Option<Vec<Vec<FieldElement>>>) {
        let mut traces = vec![];
        for i in 0..self.num_signer {
            let lamport_plus = LamportPlus::new();
            let (message_bits, _) = LamportPlus::mine_message_sha512(&self.messages[i], 5).unwrap();
            let (is_valid, trace) = lamport_plus.verify_with_trace_agg(&message_bits, &self.signs[i], &self.pub_accs[i]);
            if is_valid {
                traces.extend(trace.into_iter().map(|row| row.to_vec()));
            } else {
                return (false, None);
            }
        }
        (true, Some(traces))
    }
     

    // 境界制約の定義
    pub fn boundary_constraints(&self) -> Vec<(usize, usize, FieldElement)> {
        // (step, register, value)
        let mut constraints: Vec<(usize, usize, FieldElement)> = vec![];

        for signer_index in 0..self.num_signer {
            let offset: usize = (signer_index  + 1) * 1024 - 1;
            let zero = self.field.zero();
            let (message_bits,_) = LamportPlus::mine_message_sha512(&self.messages[signer_index], 5).unwrap();
            // メッセージビットを分割して数値に変換
            let (m0, m1) = split_and_parse_bits(&message_bits).unwrap();
            let step = signer_index as usize * 1024;

            /*  
                Values in all registers except for 𝑟2, 𝑟3, 𝑟4, 𝑟5, 𝑟10, 𝑟11 must
                be equal to zeros at the first step of the computation (𝑠0).
            */
            constraints.push((step, 0, zero));
            constraints.push((step, 1, zero));
            constraints.push((step, 6, zero));
            constraints.push((step, 7, zero));
            constraints.push((step, 8, zero));
            constraints.push((step, 9, zero));
            constraints.push((step, 12, zero));
            constraints.push((step, 13, zero));
            constraints.push((step, 14, zero));
            constraints.push((step, 15, zero));
            constraints.push((step, 16, zero));
            constraints.push((step, 17, zero));
            constraints.push((step, 18, zero));
            constraints.push((step, 19, zero));
            constraints.push((step, 20, zero));
            constraints.push((step, 21, zero));

            /*
                Values in registers𝑟0 and 𝑟1 must be equal to message values
                𝑚0 and 𝑚1 at step 𝑠1023 (the last step of the computation).
            */
            constraints.push((offset, 0, FieldElement::new(m0, self.field)));
            constraints.push((offset, 1, FieldElement::new(m1, self.field)));

            /*
            Values in 𝑟16 and 𝑟17 at step 𝑠1023 must be equal to the values
            of the public key 𝑝𝑢𝑏 which was used to sign the message 
            */
            constraints.push((offset, 16, self.pub_accs[signer_index][0]));
            constraints.push((offset, 17, self.pub_accs[signer_index][1]));
        }
        constraints
    }
    
    // 遷移制約の定義
    pub fn generate_transition_constraints(&self)  -> Vec<MPolynomial>{
        // Mpolynoamialの構造 [[register, exponent], coefficient]
        let mut constraints: Vec<MPolynomial> = vec![];

        for _ in 0..self.num_signer {
            let rescue_prime = rescue_prime::RescuePrime::new();
            for step in 0..1024 {
                // 各ステップの遷移制約を定義

                // 周期
                let m_h: u128 = if step % 8 == 7 { 1 } else { 0 };
                let m_p: u128 = 1 << (step / 8);
                let m_s: u128 = if step % 1024 == 1023 { 1 } else { 0 };
                /*
                ビットであることを確認する制約
                (1-m_s) * (r_2^2 − r_2) = 0  (1)
                (1-m_s) * (r_3^2 − r_3) = 0  (2)
                */
                for reg in 2..4 {
                    // (1-m_s) * (r_reg^2 - r_reg) = 0
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg, 2)].into_iter().collect(), Field::one(self.field));
                    let mut dict2 = HashMap::new();
                    dict2.insert([(reg, 1)].into_iter().collect(), Field::one(self.field));

                    let diff_poly = &MPolynomial::new(dict1) - &MPolynomial::new(dict2);
                    let constraint = MPolynomial::scale_polynomial(&diff_poly, &FieldElement::new(1 - m_s, self.field));
                    constraints.push(constraint);   
                }
                /* 
                メッセージの累積値を確認する制約
                (1-m_s) * (r_0' − (r_0 + m_h * m_p * r_2)) = 0  (3)
                (1-m_s) * (r_1' − (r_1 + m_h * m_p * r_3)) = 0  (4)
                */
                for reg in 0..2 {
                    // r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_reg
                    let mut dict2 = HashMap::new();
                    dict2.insert([(reg, 1)].into_iter().collect(), Field::one(self.field));
                    // m_h * m_p * r_(reg+2)
                    let mut dict3 = HashMap::new();
                    dict3.insert([(reg + 2, 1)].into_iter().collect(), FieldElement::new(m_h * m_p, self.field));
    
                    let diff_poly = &MPolynomial::new(dict1)
                        - &(&MPolynomial::new(dict2) + &MPolynomial::new(dict3));
    
                    let constraint = MPolynomial::scale_polynomial(&diff_poly, &FieldElement::new(1 - m_s, self.field));
                    constraints.push(constraint);
                }
                
                /* 
                ・公開鍵の左半分のRescueハッシュの内部制約
                (1-m_s) * (1 − m_h) * resc_0(r_4, r'_4) = 0  (5)
                (1-m_s) * (1 − m_h) * resc_1(r_5, r'_5) = 0  (6)
                (1-m_s) * (m_h * r'_6 + (1 − m_h) * resc_2(r_6, r'_6)) = 0  (7)
                (1-m_s) * (m_h * r'_7 + (1 − m_h) * resc_3(r_7, r'_7)) = 0  (8)
                (1-m_s) * (m_h * r'_8 + (1 − m_h) * resc_4(r_8, r'_8)) = 0  (9)
                (1-m_s) * (m_h * r'_9 + (1 − m_h) * resc_5(r_9, r'_9)) = 0  (10)
                */
                let left_pub_keys_air = rescue_prime.rescue_air_round(4, step);
                // (1-m_s) * (1 − m_h) * resc_0(r_4, r'_4) = 0  (5)
                let constraint5 = 
                    MPolynomial::scale_polynomial(&left_pub_keys_air, &FieldElement::new((1-m_s) * (1 - m_h), self.field));
                constraints.push(constraint5.clone());
                // (1-m_s) * (1 − m_h) * resc_1(r_5, r'_5) = 0  (6) (5)と一緒
                let constraint6 = constraint5.clone();
                constraints.push(constraint6);

                for reg in 6..10 {
                    // m_h * r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), FieldElement::new(m_h, self.field));

                    // (1 − m_h) * resc
                    let constraint = MPolynomial::scale_polynomial(&left_pub_keys_air, &FieldElement::new(1 - m_h, self.field));

                    // (m_h * r'_i + (1 − m_h) * resc
                    let combined_poly 
                        = &MPolynomial::new(dict1) + &constraint;
                    
                    // //(1-m_s) * (m_h * r'_i + (1 − m_h) * resc = 0
                    let constraint = 
                    MPolynomial::scale_polynomial(&combined_poly, &FieldElement::new(1-m_s, self.field));
                    constraints.push(constraint);
                }
                /*
                署名の右半分を検証する際の制約
                (1-m_s) * (1 − m_h) * resc_0(r_{10}, r'_{10}) = 0  (11)
                (1-m_s) * (1 − m_h) * resc_1(r_{11}, r'_{11}) = 0  (12)
                (1-m_s) * (m_h * r'_{12} + (1 − m_h) * resc_2(r_{12}, r'_{12})) = 0  (13)
                (1-m_s) * (m_h * r'_{13} + (1 − m_h) * resc_3(r_{13}, r'_{13})) = 0  (14)
                (1-m_s) * (m_h * r'_{14} + (1 − m_h) * resc_4(r_{14}, r'_{14})) = 0  (15)
                (1-m_s) * (m_h * r'_{15} + (1 − m_h) * resc_5(r_{15}, r'_{15})) = 0  (16) 
                */
                let right_pub_keys_air = rescue_prime.rescue_air_round(10, step);
                // (1-m_s) * (1 − m_h) * resc (11)
                let constraint11 = 
                    MPolynomial::scale_polynomial(&right_pub_keys_air, &FieldElement::new((1-m_s) * (1 - m_h), self.field));
                constraints.push(constraint11.clone());
                // (1-m_s) * (1 − m_h) * resc = 0  (12) 11と一緒
                let constraint12 = constraint11.clone();
                constraints.push(constraint12);

                for reg in 12..16 {
                    // m_h * r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), FieldElement::new(m_h, self.field));

                    // (1 − m_h) * resc
                    let resc_poly = 
                        MPolynomial::scale_polynomial(&right_pub_keys_air, &FieldElement::new(1 - m_h, self.field));
                    // (m_h * r_i' + ((1 − m_h) * resc))
                    let conbined_poly = &MPolynomial::new(dict1) + &resc_poly;

                    // (1 - m_s) * (m_h * r_i' + ((1 − m_h) * resc))
                    let constraint = 
                        MPolynomial::scale_polynomial(&conbined_poly, &FieldElement::new(1 - m_h, self.field));
                    constraints.push(constraint);
                }
                
                /*
                ・公開鍵アキュムレータの制約
                (1-m_s) * (m_h * r_2 * (r'_{16} − r_4) + (1 − m_h) * resc_0(r_{16}, r'_{16})) = 0  (17)
                (1-m_s) * (m_h * r_2 * (r'_{17} − r_5) + (1 − m_h) * resc_1(r_{17}, r'_{17})) = 0  (18)
                (1-m_s) * (m_h * r_3 * (r'_{18} − r_{10}) + (1 − m_h) * resc_2(r_{18}, r'_{18})) = 0  (19)
                (1-m_s) * (m_h * r_3 * (r'_{19} − r_{11}) + (1 − m_h) * resc_3(r_{19}, r'_{19})) = 0  (20)
                (1-m_s) * (m_h * (r'_{20} − r_{20}) + (1 − m_h) * resc_4(r_{20}, r'_{20})) = 0  (21)
                (1-m_s) * (m_h * (r'_{21} − r_{21}) + (1 − m_h) * resc_5(r_{21}, r'_{21})) = 0  (22)
                */
                let pub_acc = rescue_prime.rescue_air_round(16, step);
                
                for reg in 16..18 {
                    // r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_{reg-12}
                    let mut dict2 = HashMap::new();
                    dict2.insert([(reg - 12, 1)].into_iter().collect(), Field::one(self.field));
                    // m_h * r_2
                    let mut dict3 = HashMap::new();
                    dict3.insert([(2, 1)].into_iter().collect(), FieldElement::new(m_h, self.field));

                    // m_h * r_2 * (r'_reg − r_{reg-12})
                    let left_poly 
                        = &MPolynomial::new(dict3) * &(&MPolynomial::new(dict1) - &MPolynomial::new(dict2));

                    // (1 − m_h) * resc
                    let right_poly = 
                        MPolynomial::scale_polynomial(&pub_acc, &FieldElement::new( 1-m_h, self.field));
                    
                    // (1-m_s) * (m_h * r_2 * (r'_reg − r_{reg-12}) + (1 − m_h) * resc) = 0
                    let combined_poly = &left_poly + &right_poly;
                    let constraint = 
                        MPolynomial::scale_polynomial(&combined_poly, &FieldElement::new( 1-m_s, self.field));
                    constraints.push(constraint);
                }

                for reg in 18..20 {
                    // r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_{reg-8}
                    let mut dict2 = HashMap::new();
                    dict2.insert([(reg - 8, 1)].into_iter().collect(), Field::one(self.field));

                    // m_h * r_3
                    let mut dict3 = HashMap::new();
                    dict3.insert([(3, 1)].into_iter().collect(), FieldElement::new(m_h, self.field));

                    // m_h * r_3 * (r'_reg − r_{reg-8})
                    let left_poly 
                        = &MPolynomial::new(dict3) * &(&MPolynomial::new(dict1) - &MPolynomial::new(dict2));

                    // (1 − m_h) * resc
                    let right_poly = 
                        MPolynomial::scale_polynomial(&pub_acc, &FieldElement::new( 1-m_h, self.field));
                    
                    // (1-m_s) * (   m_h * r_3 * (r'_reg − r_{reg-8}) + (1 − m_h) * resc)   ) = 0
                    let conbined_poly = &left_poly + &right_poly;
                    let constraint = 
                        MPolynomial::scale_polynomial(&conbined_poly, &FieldElement::new( 1-m_s, self.field));
                    constraints.push(constraint);
                }

                for reg in 20..22 {
                    // r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_reg
                    let mut dict2 = HashMap::new();
                    dict2.insert([(reg, 1)].into_iter().collect(), Field::one(self.field));
                    // (m_h * (r_reg' − r_{reg}))
                    let left_poly 
                        = MPolynomial::scale_polynomial(&(&MPolynomial::new(dict1) - &MPolynomial::new(dict2)), &FieldElement::new(m_h, self.field));

                    // (1 − m_h) * resc
                    let right_poly = 
                        MPolynomial::scale_polynomial(&pub_acc, &FieldElement::new( 1-m_h, self.field));
                    
                    // (1-m_s) * (   m_h * (r_reg' − r_reg)   +   (1 − m_h) * resc   ) = 0  (21)
                    let conbined_poly = &left_poly + &right_poly;
                    let constraint = 
                        MPolynomial::scale_polynomial(&conbined_poly, &FieldElement::new( 1-m_s, self.field));
                    constraints.push(constraint);
                }
           }
        }
        constraints
    }
    
    // 集約証明の生成
    pub fn prove(&self, proofstream: &mut ProofStream) {
        // 各署名の検証とトレースの生成
        let (is_valid, traces) = self.verify_each_sign();
        if !is_valid {
            panic!("One or more signatures are invalid.");
        }
        let mut traces = traces.unwrap();

        // 境界制約の生成
        let boundary_constraints = self.boundary_constraints();

        // 遷移制約の生成
        let transition_constraints = self.generate_transition_constraints();

        // STARK証明の生成
        self.stark.prove(&mut traces, &transition_constraints, &boundary_constraints, proofstream);
    }
    // 集約証明の検証
    pub fn verify(&self, transition_constraints: &Vec<MPolynomial>, boundary: &Vec<(usize, usize, FieldElement)>, proof_stream: &mut ProofStream) -> bool {
        // STARK証明の検証
        self.stark.verify(transition_constraints, boundary, proof_stream)
    }

}

// メッセージビットを受け取り、公開鍵、署名を生成する関数
pub fn lamport_plus_signature(
    message: &[u8],
) -> (Vec<[FieldElement; 2]>, Vec<[FieldElement; 2]>,[FieldElement; 2]) {
    let mined_bits = LamportPlus::mine_message_sha512(message, 5).unwrap().0;
    let mut lamport_plus = LamportPlus::new();
    let (pr, pb) = lamport_plus.keygen(&mined_bits);
    let sig = lamport_plus.sign(&mined_bits, &pr);
    (pb, sig, lamport_plus.pub_acc)
}

// トレースを数値(FieldElement)の形式で作成→多項式補間により代数表現に変換(STARKでできる)
// ・制約の表現 Polynomail-Polynomail

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lamport_plus::LamportPlus;
    use modulus::FieldElement;
    use crate::proofstream::ProofStream;
    use crate::rescue_prime::RescuePrime;

    #[test]
    fn test_agg_sig() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = modulus::Field::new(p);
        let num_signer = 2; // 署名者の数
        let messages = vec![b"message1".to_vec(), b"message2".to_vec()]; // メッセージ
        let (pb1, sig1, pub_acc1) = lamport_plus_signature(&messages[0]);
        let (pb2, sig2, pub_acc2) = lamport_plus_signature(&messages[1]);
        
        let  pub_keys = vec![pb1, pb2]; 
        let  signs = vec![sig1, sig2]; // 署名
        let pub_accs = vec![pub_acc1, pub_acc2]; // 公開鍵アキュムレータ
        

        let agg_sig = AggSig::new(
            2,
            messages,
            pub_keys,
            pub_accs,
            signs,
            field,
            8,
            27,
            96,
            22,
            1024,
            7,
        );

        let mut proof_stream = ProofStream::new();
        agg_sig.prove(&mut proof_stream);

        assert!(agg_sig.verify(&agg_sig.generate_transition_constraints(), &agg_sig.boundary_constraints(), &mut proof_stream));
    }
}
