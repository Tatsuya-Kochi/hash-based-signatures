use std::collections::{HashMap, BTreeMap};
use crate::merkle::Merkle;
use crate::modulus;
use crate::mpolynomial::MPolynomial;
use crate::rescue_prime;
use modulus::{Field, FieldElement};
use crate::lamport_plus::{LamportPlus, split_and_parse_bits};
use crate::stark::Stark;
use rand::Rng;
use crate::proofstream::ProofStream;

pub struct ThresholdSig{
    pub num_total_signers: usize, // 署名者の総数
    pub num_signed_signers: usize, // 署名を返した者の数
    pub pub_keys: Vec<Vec<[FieldElement; 2]>>, // 全ての公開鍵
    pub pub_accs: Vec<[FieldElement; 2]>, // 全ての公開鍵アキュムレータ
    pub signed_pub_keys: Vec<Vec<[FieldElement; 2]>>, // 署名に使われた公開鍵
    pub signed_pub_accs: Vec<[FieldElement; 2]>, // 署名に使われた公開鍵アキュムレータ pub_accsと同じ順番で
    pub signs: Vec<Vec<[FieldElement; 2]>>, // 署名
    pub message: Vec<u8>, // 単一のメッセージ
    pub field: Field,
    pub expansion_factor: usize,
    pub num_colinearity_checks: usize,
    pub security_level: usize,
    pub num_registers: usize,
    pub num_cycles: usize,
    pub transition_constraints_degree: usize,
    pub stark: Stark, //STARKインスタンス
}

impl ThresholdSig {
    // 署名者の数、メッセージ、公開鍵、署名、トレース
    pub fn new(
        num_total_signers: usize,
        num_signed_signers: usize,
        pub_keys: Vec<Vec<[FieldElement; 2]>>,
        pub_accs: Vec<[FieldElement; 2]>,
        signed_pub_keys: Vec<Vec<[FieldElement; 2]>>,
        signed_pub_accs: Vec<[FieldElement; 2]>,
        message: Vec<u8>,
        signs: Vec<Vec<[FieldElement; 2]>>,
        field: Field,
        expansion_factor: usize,
        num_colinearity_checks: usize,
        security_level: usize,
        num_registers: usize,
        num_cycles: usize, // サイクル数 num_total_signers以上の最小の2のべき乗
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
        ThresholdSig { 
            num_total_signers,
            num_signed_signers, 
            pub_keys, 
            pub_accs,
            signed_pub_keys,
            signed_pub_accs,
            message, 
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

    // Merkleツリーの構築
    pub fn generate_merkle_tree(&mut self) -> (Vec<FieldElement>, Vec<Vec<FieldElement>>) {
        // 署名者の公開鍵アキュムレータからマークルツリーを生成
        // 最後の葉はゼロの値を持つ
        // 2のべき乗の長さを持つようにダミーの葉を追加
        let leaf_length = self.num_total_signers.next_power_of_two();
        self.num_cycles = leaf_length; // 全サイクル数を更新
        let mut leafs: Vec<Vec<FieldElement>> = self.pub_accs.clone().to_vec()
            .into_iter()
            .map(|acc| vec![acc[0].clone(), acc[1].clone()])
            .collect();
        let mut rng = rand::thread_rng();
        for i in leafs.len()..leaf_length {
            if i == leaf_length - 1 {
                // 最後の葉はゼロの公開鍵アキュムレータ
                leafs.push(vec![self.field.zero(), self.field.zero()]);
                continue;
            }
            let random_byte1: [u8; 16] = rng.gen();  // 128ビット乱数
            let random_byte2: [u8; 16] = rng.gen();  // 128ビット乱数
            let random_bit1 = FieldElement::new(u128::from_be_bytes(random_byte1), self.field);
            let random_bit2 = FieldElement::new(u128::from_be_bytes(random_byte2), self.field);
            leafs.push(vec![random_bit1,random_bit2]);
        }
        // マークルツリーの生成
        let merkle = Merkle::new();
        let root = merkle.rescue_commit(&leafs);
        (root, leafs)
    }

    // 一つ一つの署名の検証と共にトレースを生成 ここで公開鍵アキュムレータの値を保持しておく必要がある
    pub fn verify_each_sign(&self, message_bits: &String, root: &Vec<FieldElement>, leafs: &Vec<Vec<FieldElement>>) -> (usize, Option<Vec<Vec<FieldElement>>>) {
        let mut total_is_valid = 0;
        let mut full_traces = vec![];
        
        
        // 検証とトレースの生成
        for i in 0..self.num_cycles {
            let mut lamport_plus = LamportPlus::new();
            // 1サイクルのトレース
            let mut trace = vec![[Field::zero(self.field); 28]; 1024];
            // 受け取った公開鍵アキュムレータが全体の公開鍵アキュムレータに含まれているか
            let exists = self.signed_pub_accs.iter().any(|item| *item == self.pub_accs[i]);
            // 署名のインデックスを保持
            let index_opt = self.signed_pub_accs
                .iter()
                .position(|item| *item == self.pub_accs[i]).unwrap();
            let mut merkle = Merkle::new();
            let lamport_trace;
            let acc_trace;       
            let signature_verif;
            let acc_verif;
            // 署名済みの公開鍵アキュムレータが存在しないなら架空の公開鍵を生成して署名を作成し、トレースを生成
            if !exists {
                // 架空の公開鍵と署名を生成し、署名検証
                let (pr, _) = lamport_plus.keygen(&message_bits);
                let sign = lamport_plus.sign(&message_bits, &pr);
                (signature_verif, lamport_trace) = lamport_plus.verify_with_trace_threshold(&message_bits, &sign, &lamport_plus.pub_acc);

                // 最初は最後のleafの検証
                if i == 0 {
                    let last_index = leafs.len()-1;
                    // Merkleパスの取得
                    let merkle_path = merkle.rescue_open_thereshold(last_index, &leafs);
                    // Merkleパスの検証
                    (acc_verif, acc_trace) = merkle.rescue_verify_threshold(&root, last_index, &merkle_path);
                }
                else {
                    // Merkleパスの取得
                    let merkle_path = merkle.rescue_open_thereshold(i, &leafs);
                    // Merkleパスの検証
                    (acc_verif, acc_trace) = merkle.rescue_verify_threshold(&root, i, &merkle_path);
                }
            }
            else {
                // 署名の検証
                (signature_verif, lamport_trace) = lamport_plus.verify_with_trace_threshold(&message_bits, &self.signs[index_opt], &self.pub_accs[i]);
                // 最初は最後のleafの検証
                if i == 0 {
                    let last_index = leafs.len()-1;
                    // Merkleパスの取得
                    let merkle_path = merkle.rescue_open_thereshold(last_index, &leafs);
                    // Merkleパスの検証
                    (acc_verif, acc_trace) = merkle.rescue_verify_threshold(&root, last_index, &merkle_path);
                }
                else {
                    // Merkleパスの取得
                    let merkle_path = merkle.rescue_open_thereshold(i, &leafs);
                    // Merkleパスの検証
                    (acc_verif, acc_trace) = merkle.rescue_verify_threshold(&root, i, &merkle_path);
                }
                // レジスタ26の更新
                trace[1024][26] = Field::one(self.field);
            }
        
            // 署名のトレースとMerkleツリーのトレース
            for j in 0..1024 {
                trace[j][0..18].copy_from_slice(&lamport_trace[j]);
                trace[j][18..26].copy_from_slice(&acc_trace[j]);
            }
            // 送られた公開鍵と署名の検証
            let verif = signature_verif as usize * acc_verif as usize;
            total_is_valid += verif;
            full_traces.extend(trace.into_iter().map(|row| row.to_vec()));
        }
        (total_is_valid, Some(full_traces))
    } 

    // 境界制約の定義
    pub fn generate_boundary_constraints(&self, leafs: &Vec<Vec<FieldElement>>) -> Vec<(usize, usize, FieldElement)> {
        // (step, register, value)
        let mut constraints: Vec<(usize, usize, FieldElement)> = vec![];

        for signer_index in 0..self.num_cycles {
            let last_step: usize = (signer_index  + 1) * 1024 - 1;
            let zero = self.field.zero();
            let step = signer_index as usize * 1024;

            /*  
                Values in all registers except for 𝑟0, 𝑟1, 𝑟6, 𝑟7 must
                be equal to zeros at the first step of the computation (𝑠0).
                    In signature verification
            */
            constraints.push((step, 2, zero));
            constraints.push((step, 3, zero));
            constraints.push((step, 4, zero));
            constraints.push((step, 5, zero));
            constraints.push((step, 8, zero));
            constraints.push((step, 9, zero));
            constraints.push((step, 12, zero));
            constraints.push((step, 13, zero));
            constraints.push((step, 14, zero));
            constraints.push((step, 15, zero));
            constraints.push((step, 16, zero));
            constraints.push((step, 17, zero));

            /*
                The above arrangement also dictates that the last leaf in the
                Merkle tree of the aggregated public key is always a zero
                key. Thus, we also impose boundary constraints enforcing
                that values in registers 𝑟18 and 𝑟19 at step 0 are set to zero.
            */
            constraints.push((step, 18, zero));
            constraints.push((step, 19, zero));

            /*
                Value in register 𝑟18 at the last step must equal the leaf index.
            */
            if signer_index == 0 {
                constraints.push((last_step, 18, FieldElement::new((leafs.len()-1) as u128, self.field)));
            }
            else {
                constraints.push((last_step, 18, FieldElement::new((signer_index-1) as u128, self.field))); 
            }
            


            // Value in register 𝑟27 at step 0 must be set to zero.
            constraints.push((step, 27, zero));

            /*
              Value in register 𝑟27 at the last step must be equal to the
              expected number of valid signatures.
            */
            constraints.push((last_step, 27, FieldElement::new(self.num_signed_signers as u128, self.field)));

        }
        constraints
    }
    
    // 遷移制約の定義
    pub fn generate_transition_constraints(&self)  -> Vec<MPolynomial>{
        // Mpolynoamialの構造 [[register, exponent], coefficient]
        let mut constraints: Vec<MPolynomial> = vec![];
        let (message_bits,_) = LamportPlus::mine_message_sha512(&self.message, 5).unwrap();
            // メッセージビットを分割して数値に変換
        let (m0, m1) = split_and_parse_bits(&message_bits).unwrap();

        for _ in 0..self.num_total_signers {
            let rescue_prime = rescue_prime::RescuePrime::new();
            for step in 0..1024 {
                // 各ステップの遷移制約を定義

                // 周期
                let m_h: u128 = if step % 8 == 7 { 1 } else { 0 };
                let m_p: u128 = 1 << (step / 8);
                let m_s: u128 = if step % 1024 == 1023 { 1 } else { 0 };
                
                /*
                ・署名検証の累積確認のための制約
                r_26^2 - r_26 = 0 (1)
                r_27' - (r_27 + m_s * r_26) = 0 (2)
                𝑚_𝑠 · 𝑟_26 · (𝑟_18' − 𝑟_12) = 0 (3)
                𝑚_𝑠 · 𝑟_26 · (𝑟_19' − 𝑟_13) = 0 (4)
                */
                // r_26^2 - r_26 = 0 (1)
                let mut dict1 = HashMap::new();
                dict1.insert([(26, 2)].into_iter().collect(), Field::one(self.field));
                let mut dict2 = HashMap::new();
                dict2.insert([(26, 1)].into_iter().collect(), Field::one(self.field));
                let constraint1 = &MPolynomial::new(dict1) - &MPolynomial::new(dict2);
                constraints.push(constraint1);
                // r_27' - (r_27 + m_s * r_26) = 0 (2)
                let mut dict1 = HashMap::new();
                dict1.insert([(27 + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                let mut dict2 = HashMap::new();
                dict2.insert([(27, 1)].into_iter().collect(), Field::one(self.field));
                let mut dict3 = HashMap::new();
                dict3.insert([(26, 1)].into_iter().collect(), FieldElement::new(m_s, self.field));
                let constraint2 = &MPolynomial::new(dict1) - &(&MPolynomial::new(dict2) + &MPolynomial::new(dict3));
                constraints.push(constraint2);
                // 𝑚_𝑠 · 𝑟_26 · (𝑟_18' − 𝑟_12) = 0 (3)
                let mut dict1 = HashMap::new();
                dict1.insert([(26, 1)].into_iter().collect(), FieldElement::new(m_s, self.field));
                let mut dict2 = HashMap::new();
                dict2.insert([(18 + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                let mut dict3 = HashMap::new();
                dict3.insert([(12, 1)].into_iter().collect(), Field::one(self.field));
                let constraint3 = &MPolynomial::new(dict1) * &(&MPolynomial::new(dict2) - &MPolynomial::new(dict3));
                constraints.push(constraint3);
                // 𝑚_𝑠 · 𝑟_26 · (𝑟_19' − 𝑟_13) = 0 (4)
                let mut dict1 = HashMap::new();
                dict1.insert([(26, 1)].into_iter().collect(), FieldElement::new(m_s, self.field));
                let mut dict2 = HashMap::new();
                dict2.insert([(19 + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                let mut dict3 = HashMap::new();
                dict3.insert([(13, 1)].into_iter().collect(), Field::one(self.field));
                let constraint4 = &MPolynomial::new(dict1) * &(&MPolynomial::new(dict2) - &MPolynomial::new(dict3));
                constraints.push(constraint4);

                /*
                ・マークルツリーの内部制約
                r_19' - r_19 = 0 (5)
                r_18' - r_18 - r_19 * m_h * m_p = 0 (6)
                m_h * (r_20' - r_19 * r_22 - (1 - r_19) * r_20) + (1 - m_h) * resc = 0 (7)
                m_h * (r_21' - r_19 * r_23 - (1 - r_19) * r_21) + (1 - m_h) * resc = 0 (8)
                m_h * (r_22' - r_19 * r_20 - (1 - r_19) * r_22) + (1 - m_h) * resc = 0 (9)
                m_h * (r_23' - r_19 * r_21 - (1 - r_19) * r_23) + (1 - m_h) * resc = 0 (10)
                m_h * r_24' + (1 - m_h) * resc = 0 (11)
                m_h * r_25' + (1 - m_h) * resc = 0 (12)
                */
                // r_19' - r_19 = 0 (5)
                let mut dict_19_next: HashMap<BTreeMap<usize, usize>, FieldElement> = HashMap::new();
                dict_19_next.insert([(19 + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                let mut dict_19: HashMap<BTreeMap<usize, usize>, FieldElement> = HashMap::new();
                dict_19.insert([(19, 1)].into_iter().collect(), Field::one(self.field));
                let constraint5 = &MPolynomial::new(dict_19_next) - &MPolynomial::new(dict_19);
                constraints.push(constraint5);
                // r_18' - r_18 - r_19 * m_h * m_p = 0 (6)
                let mut dict_18_next: HashMap<BTreeMap<usize, usize>, FieldElement> = HashMap::new();
                dict_18_next.insert([(18 + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                let mut dict_18: HashMap<BTreeMap<usize, usize>, FieldElement> = HashMap::new();
                dict_18.insert([(18, 1)].into_iter().collect(), Field::one(self.field));
                let mut dict_19_mhmp: HashMap<BTreeMap<usize, usize>, FieldElement> = HashMap::new();
                dict_19_mhmp.insert([(19, 1)].into_iter().collect(), FieldElement::new(m_h*m_p, self.field));
                let constraint6 = &MPolynomial::new(dict_18_next) - &(&MPolynomial::new(dict_18) - &MPolynomial::new(dict_19_mhmp));
                constraints.push(constraint6);


                let merkle_resc = rescue_prime.rescue_air_round(20, step);
                for reg in 20..22 {
                    // r_reg'
                    let mut dict_reg_n = HashMap::new();
                    dict_reg_n.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_19
                    let mut dict_19 = HashMap::new();
                    dict_19.insert([(19, 1)].into_iter().collect(), Field::one(self.field));
                    // r_(reg+2)
                    let mut dict_reg2 = HashMap::new();
                    dict_reg2.insert([(reg + 2, 1)].into_iter().collect(), FieldElement::new(1, self.field));
                    // 1
                    let mut dict_1 = HashMap::new();
                    dict_1.insert([].into_iter().collect(), FieldElement::new(1, self.field));
                    // r_reg
                    let mut dict_reg = HashMap::new();
                    dict_reg.insert([(reg, 1)].into_iter().collect(), FieldElement::new(1, self.field));
                    // 1 - m_h
                    let mut dict_1mh: HashMap<BTreeMap<usize, usize>, FieldElement> = HashMap::new();
                    dict_1mh.insert([].into_iter().collect(), FieldElement::new(1 - m_h, self.field));
                    // r_reg' - r_19 * r_(reg+2) - (1 - r_19) * r_reg
                     // 計算順序チェック
                    let temp_poly1 = 
                        &(&MPolynomial::new(dict_reg_n) - &(&MPolynomial::new(dict_19.clone()) * &MPolynomial::new(dict_reg2))) - &(&(&MPolynomial::new(dict_1) - &MPolynomial::new(dict_19)) * &MPolynomial::new(dict_reg));
                    // m_h * (r_reg' - r_19 * r_(reg+2) - (1 - r_19) * r_reg)
                    let temp_poly2 = MPolynomial::scale_polynomial(&temp_poly1, &FieldElement::new(m_h, self.field));
                    // m_h * (r_reg' - r_19 * r_(reg+2) - (1 - r_19) * r_reg) + (1 - m_h) * resc
                    let constraint = &temp_poly2 + &MPolynomial::scale_polynomial(&merkle_resc, &FieldElement::new(1 - m_h, self.field));
                    constraints.push(constraint);
                }
                for reg in 22..24 {
                    // r_reg'
                    let mut dict_reg_n = HashMap::new();
                    dict_reg_n.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_19
                    let mut dict_19 = HashMap::new();
                    dict_19.insert([(19, 1)].into_iter().collect(), Field::one(self.field));
                    // r_(reg-2)
                    let mut dict_reg2 = HashMap::new();
                    dict_reg2.insert([(reg - 2, 1)].into_iter().collect(), FieldElement::new(1, self.field));
                    // 1
                    let mut dict_1 = HashMap::new();
                    dict_1.insert([].into_iter().collect(), FieldElement::new(1, self.field));
                    // r_reg
                    let mut dict_reg = HashMap::new();
                    dict_reg.insert([(reg, 1)].into_iter().collect(), FieldElement::new(1, self.field));
                    // 1 - m_h
                    let mut dict_1mh: HashMap<BTreeMap<usize, usize>, FieldElement> = HashMap::new();
                    dict_1mh.insert([].into_iter().collect(), FieldElement::new(1 - m_h, self.field));
                    // r_reg' - r_19 * r_(reg-2) - (1 - r_19) * r_reg
                     // 計算順序チェック
                    let temp_poly1 = 
                        &(&MPolynomial::new(dict_reg_n) - &(&MPolynomial::new(dict_19.clone()) * &MPolynomial::new(dict_reg2))) - &(&(&MPolynomial::new(dict_1) - &MPolynomial::new(dict_19)) * &MPolynomial::new(dict_reg));
                    // m_h * (r_reg' - r_19 * r_(reg-2) - (1 - r_19) * r_reg)
                    let temp_poly2 = MPolynomial::scale_polynomial(&temp_poly1, &FieldElement::new(m_h, self.field));
                    // m_h * (r_reg' - r_19 * r_(reg-2) - (1 - r_19) * r_reg) + (1 - m_h) * resc
                    let constraint = &temp_poly2 + &MPolynomial::scale_polynomial(&merkle_resc, &FieldElement::new(1 - m_h, self.field));
                    constraints.push(constraint);
                }
                // m_h * r_24' + (1 - m_h) * resc = 0 (11)
                // m_h * r_25' + (1 - m_h) * resc = 0 (12)
                for reg in 24..26 {
                    // r_reg' * m_h
                    let mut dict_reg_n = HashMap::new();
                    dict_reg_n.insert([(reg + self.num_registers, 1)].into_iter().collect(), FieldElement::new(m_h, self.field));
                    // m_h * r_reg' + (1 - m_h) * resc
                    let constraint = 
                        &MPolynomial::new(dict_reg_n) +
                        &MPolynomial::scale_polynomial(&merkle_resc, &FieldElement::new(1 - m_h, self.field));
                    constraints.push(constraint);
                }
                
                /*  
                ・公開鍵の左半分のRescueハッシュの内部制約
                (1-m_s) * (1 − m_h) * resc = 0  (1)
                (1-m_s) * (1 − m_h) * resc = 0  (2)
                (1-m_s) * (m_h * r'_2 + (1 − m_h) * resc = 0  (3)
                (1-m_s) * (m_h * r'_3 + (1 − m_h) * resc = 0  (4)
                (1-m_s) * (m_h * r'_4 + (1 − m_h) * resc) = 0  (5)
                (1-m_s) * (m_h * r'_5 + (1 − m_h) * resc) = 0  (6)
                */
                let left_pub_keys_air = rescue_prime.rescue_air_round(0, step);
                // (1-m_s) * (1 − m_h) * resc = 0  (1)
                let constraint1 = 
                    MPolynomial::scale_polynomial(&left_pub_keys_air, &FieldElement::new((1-m_s) * (1 - m_h), self.field));
                constraints.push(constraint1.clone());
                // (1-m_s) * (1 − m_h) * resc = 0  (2) (1)と一緒
                let constraint2 = constraint1.clone();
                constraints.push(constraint2);

                for reg in 2..6 {
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
                (1-m_s) * (1 − m_h) * resc = 0  (7)
                (1-m_s) * (1 − m_h) * resc = 0  (8)
                (1-m_s) * (m_h * r'_8 + (1 − m_h) * resc) = 0  (9)
                (1-m_s) * (m_h * r'_9 + (1 − m_h) * resc) = 0  (10)
                (1-m_s) * (m_h * r'_10 + (1 − m_h) * resc) = 0  (11)
                (1-m_s) * (m_h * r'_11 + (1 − m_h) * resc) = 0  (12) 
                */
                let right_pub_keys_air = rescue_prime.rescue_air_round(6, step);
                // (1-m_s) * (1 − m_h) * resc (7)
                let constraint7 = 
                    MPolynomial::scale_polynomial(&right_pub_keys_air, &FieldElement::new((1-m_s) * (1 - m_h), self.field));
                constraints.push(constraint7.clone());
                // (1-m_s) * (1 − m_h) * resc = 0  (12) 11と一緒
                let constraint8 = constraint7.clone();
                constraints.push(constraint8);

                for reg in 8..12 {
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
                (1-m_s) * (m_h * 左メッセージビット * (r'_{12} − r_0) + (1 − m_h) * resc) = 0  (13)
                (1-m_s) * (m_h * 左メッセージビット * (r'_{13} − r_1) + (1 − m_h) * resc) = 0  (14)
                (1-m_s) * (m_h * 右メッセージビット * (r'_{14} − r_6) + (1 − m_h) * resc) = 0  (15)
                (1-m_s) * (m_h * 右メッセージビット * (r'_{15} − r_7) + (1 − m_h) * resc) = 0  (16)
                (1-m_s) * (m_h * (r'_{16} − r_{16}) + (1 − m_h) * resc) = 0  (17)
                (1-m_s) * (m_h * (r'_{17} − r_{17}) + (1 − m_h) * resc) = 0  (18)
                */
                let pub_acc = rescue_prime.rescue_air_round(12, step);
                
                for reg in 12..14 {
                    // r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_{reg-12}
                    let mut dict2 = HashMap::new();
                    dict2.insert([(reg - 12, 1)].into_iter().collect(), Field::one(self.field));
                    // m_h * 左メッセージビット
                    let mut dict3 = HashMap::new();
                    dict3.insert([].into_iter().collect(), FieldElement::new(m_h*m0, self.field));

                    // m_h * 左メッセージビット * (r'_reg − r_{reg-12})
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

                for reg in 15..17 {
                    // r_reg'
                    let mut dict1 = HashMap::new();
                    dict1.insert([(reg + self.num_registers, 1)].into_iter().collect(), Field::one(self.field));
                    // r_{reg-8}
                    let mut dict2 = HashMap::new();
                    dict2.insert([(reg - 8, 1)].into_iter().collect(), Field::one(self.field));

                    // m_h * 右メッセージビット
                    let mut dict3 = HashMap::new();
                    dict3.insert([].into_iter().collect(), FieldElement::new(m_h*m1, self.field));

                    // m_h * 右メッセージビット * (r'_reg − r_{reg-8})
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
    
    // 閾値証明の生成
    pub fn prove(&mut self, proofstream: &mut ProofStream) {
        let (message_bits,_) = LamportPlus::mine_message_sha512(&self.message, 5).unwrap();
        // Merkleツリーを生成し、ルートと葉を取得
        let (root, leafs) = self.generate_merkle_tree();

        // 境界制約を生成
        let boundary_constraints = self.generate_boundary_constraints(&leafs);

        // 遷移制約を生成
        let transition_constraints = self.generate_transition_constraints();

        // 個々の検証とトレースの生成
        let (total_is_valid, traces) = self.verify_each_sign(&message_bits, &root, &leafs);

        let mut traces = traces.unwrap();
        // STARK証明の生成
        self.stark.prove(&mut traces, &transition_constraints, &boundary_constraints, proofstream);
    }
    // 閾値証明の検証
    pub fn verify(&self, transition_constraints: &Vec<MPolynomial>, boundary: &Vec<(usize, usize, FieldElement)>, proof_stream: &mut ProofStream) -> bool {
        // STARK証明の検証
        self.stark.verify(transition_constraints, boundary, proof_stream)
    }

}

// トレースを数値(FieldElement)の形式で作成→多項式補間により代数表現に変換(STARKでできる)
// ・制約の表現 Polynomail-Polynomail

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lamport_plus::LamportPlus;
    use modulus::FieldElement;
}
