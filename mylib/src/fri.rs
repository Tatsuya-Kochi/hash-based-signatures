use blake3;
use crate::modulus::{self, FieldElement};
use modulus::Field as Field;
use crate::merkle::{Merkle, prepare_data};
use crate::proofstream::ProofStream;
use crate::polynomial::Polynomial;

pub struct Fri {
    offset: FieldElement,  // 評価ドメインの初期オフセット
    pub omega: FieldElement, // 評価ドメインの生成元（根）
    pub domain_length: u128,  // 評価ドメインの長さ
    pub field: Field,
    pub expansion_factor: usize, // コードワードの拡張係数
    pub num_colinearity_tests: usize, // 1ラウンドで行う線形性チェックの回数
}

impl Fri {
    pub fn new(offset: FieldElement, omega: FieldElement, domain_length: u128, expansion_factor: usize, num_colinearity_tests: usize) -> Self {
        Self {
            offset,
            omega,
            domain_length,
            field: omega.field,
            expansion_factor,
            num_colinearity_tests,
        }
    }

    // コードワード長をexpansion_factor 以下にするまで、何回折りたたむかを計算
    pub fn num_rounds(&self) -> u128 {
        let mut codeword_length = self.domain_length;
        let mut num_rounds = 0;
        while codeword_length > self.expansion_factor as u128 && (4 * self.num_colinearity_tests as u128) < codeword_length {
            codeword_length /= 2;
            num_rounds += 1;
        }
        num_rounds
    }

    // オフセットから評価ドメインを生成
    pub fn eval_domain(&self) -> Vec<FieldElement> {
        (0..self.domain_length)
            .map(|i| &self.offset * &self.omega.pow(i as u128))
            .collect()
    }

    // 
    pub fn sample_index(&self, byte_array: &[u8], size: usize) -> usize {
        let mut acc: usize = 0;
        for &b in byte_array {
            acc = (acc << 8) ^ (b as usize);
        }
        acc % size
    }

    // 
    pub fn sample_indices(&self, seed: Vec<u8>, size: usize, reduced_size: usize, number: usize) -> Result<Vec<u128>, String> {
        if number > reduced_size {
            return Err(format!("cannot sample more indices than available in last codeword; requested: {}, available: {}", number, reduced_size));
        }
        if number > 2 * reduced_size {
            return Err("not enough entropy in indices wrt last codeword".to_string());
        }

        let mut indices: Vec<u128> = Vec::new();
        let mut reduced_indices = Vec::new();
        let mut counter: i32 = 0;

        while indices.len() < number {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&seed);
            hasher.update(&counter.to_le_bytes());
            let hash = hasher.finalize();

            let index = self.sample_index(hash.as_bytes(), size);
            let reduced_index = index % reduced_size;

            if !reduced_indices.contains(&reduced_index) {
                indices.push(index as u128);
                reduced_indices.push(reduced_index);
            }

            counter += 1;
        }

        Ok(indices)
    }

    // 多項式補間により、3点が1次多項式上にあるかをチェック
    pub fn test_colinearity(points: Vec<Vec<FieldElement>>) -> bool {
        let domain: Vec<FieldElement> = points.iter().map(|p| p[0].clone()).collect();
        let values: Vec<FieldElement> = points.iter().map(|p| p[1].clone()).collect();
        let polynomial: Polynomial = Polynomial::interpolate_domain(&domain, &values);
        polynomial.degree() == 1
    }

    // コードワードをコミットし、各ラウンドのコードワードを返す
    // codeword: 多項式の評価値、proof_stream: 証明ストリーム
    pub fn prove(&self, codeword: Vec<FieldElement>, proof_stream: &mut ProofStream) -> Result<Vec<u128>, String> {
        if self.domain_length != codeword.len() as u128 {
            return Err("initial codeword length does not match length of initial codeword".to_string());
        }

        let codewords = self.commit(codeword, proof_stream);

        // インデックスのサンプリング 
        let top_level_indices = self.sample_indices(
            proof_stream.prover_fiat_shamir(32),
            codewords[1].len(),
            codewords[codewords.len() - 1].len(),
            self.num_colinearity_tests,
        );

        // インデックスの初期化
        let mut indices = match top_level_indices.clone() {
            Ok(v) => v,
            Err(e) => {
                println!("err value = {}", e);
                return Err(e);
            }
        };
        println!("indices_length: {}", indices.len());

        // FRIラウンドごとの証明データ抽出
        for i in 0..(codewords.len() - 1) {
            indices = indices.iter().map(|&index| index % (codewords[i].len() / 2) as u128).collect();
            println!("round {}, codewords[i].len() = {}, expected = {}", i, codewords[i].len(), self.domain_length >> i);
            self.query(&codewords[i], &codewords[i + 1], &indices, proof_stream);
        }

        Ok(indices)
    }

    pub fn commit(&self, mut codeword: Vec<FieldElement>, proof_stream: &mut ProofStream) -> Vec<Vec<FieldElement>> {
        let one = self.field.one();
        let two = FieldElement::new(2, self.field);
        let mut omega = self.omega;
        let mut offset = self.offset;
        let mut codewords = vec![];

        for r in 0..self.num_rounds() {
            // マークルルートを計算し、証明ストリームに追加
            let merkle = Merkle::new();
            let root = merkle.blake_commit(&prepare_data(&codeword));
            proof_stream.push(&root);

            // フィアットシャミアからランダム値を生成
            let alpha = self.field.sample(proof_stream.prover_fiat_shamir(32));
            assert_ne!(alpha, self.field.zero());

            codewords.push(codeword.clone());

            if r == self.num_rounds() - 1 {
                break;
            }

            codeword = (0..(codeword.len() / 2))
                .map(|i| {
                    let omega_i = omega.pow(i as u128);
                    let term1 = &one + &(&alpha / &(&offset * &omega_i));
                    let term2 = &one - &(&alpha / &(&offset * &omega_i));
                    let new_value = &two.inverse() * &(&(&term1 * &codeword[i]) + &(&term2 * &codeword[codeword.len() / 2 + i]));
                    
                    new_value
                })
                .collect();

            omega = omega.pow(2);
            offset = offset.pow(2);
        }
        proof_stream.push(&codeword.clone());
        //codewords.push(codeword);
        codewords
    }

    pub fn query(
        &self,
        current_codeword: &Vec<FieldElement>,
        next_codeword: &Vec<FieldElement>,
        c_indices: &Vec<u128>,
        proof_stream: &mut ProofStream,
    ) -> Vec<u128> {
        let a_indices: Vec<u128> = c_indices.clone();
        let b_indices: Vec<u128> = c_indices.iter().map(|&index| index + current_codeword.len() as u128 / 2).collect();
        println!("a_indices: {:?}", a_indices);
        println!("b_indices: {:?}", b_indices);

        for s in 0..self.num_colinearity_tests {
            let s = s as usize;
            proof_stream.push(&vec![
                current_codeword[a_indices[s] as usize],
                current_codeword[b_indices[s] as usize],
                next_codeword[c_indices[s] as usize]
            ])
        }

        let merkle = Merkle::new();
        let current_codeword_prepared = prepare_data(&current_codeword);
        let next_codeword_prepared = prepare_data(&next_codeword);
        for s in 0..self.num_colinearity_tests {
            let path_a = merkle.blake_open(a_indices[s] as usize, &current_codeword_prepared);
            proof_stream.push(&path_a);
            let path_b = merkle.blake_open(b_indices[s] as usize, &current_codeword_prepared);
            proof_stream.push(&path_b);  
            let path_c = merkle.blake_open(c_indices[s] as usize, &next_codeword_prepared);
            proof_stream.push(&path_c);
        }

        let mut combined_indices = a_indices.clone();
        combined_indices.extend(b_indices);
        combined_indices
    }

    pub fn verify(&self, proof_stream: &mut ProofStream, polynomial_values: &mut Vec<(u128, FieldElement)>) -> bool {
        let mut omega = self.omega;
        let mut offset = self.offset;

        let mut roots = vec![];
        let mut alphas = vec![];

        // マークルルートとアルファ値を取得
        for _ in 0..self.num_rounds() {
            roots.push(proof_stream.pull::<Vec<u8>>());
            alphas.push(self.field.sample(proof_stream.verifier_fiat_shamir(32)));
        }

        // 最後の codeword を pull & 補間で確認
        let last_codeword = proof_stream.pull::<Vec<FieldElement>>();
        if roots.last().unwrap() != &Merkle::new().blake_commit(&prepare_data(&last_codeword)) {
            print!("Merkle root mismatch");
            return false;
        }

        let degree = (last_codeword.len() / self.expansion_factor) - 1;
        let mut last_omega = omega;
        let mut last_offset = offset;
        for _ in 0..(self.num_rounds()-1) {
            last_omega = &last_omega * &last_omega;
            last_offset = &last_offset * &last_offset;
        }

        if last_omega.pow((last_codeword.len() - 1) as u128).inverse() != last_omega {
            print!("Last omega does not match expected value");
            return false;
        }

        let last_domain: Vec<FieldElement> = (0..last_codeword.len())
            .map(|i| &last_offset * &last_omega.pow(i as u128))
            .collect();

        let poly = Polynomial::interpolate_domain(&last_domain, &last_codeword);

        for (i, x) in last_domain.iter().enumerate() {
            let expected = poly.evaluate(x);
            let actual = &last_codeword[i];
            if &expected != actual {
                println!("❌ mismatch at i = {}: poly({:?}) = {:?}, but codeword = {:?}", i, x, expected, actual);
            }
        }

        if poly.evaluate_domain(&last_domain) != last_codeword {
            print!("Polynomial evaluation mismatch");
            return false;
        }

        if poly.degree() as usize > degree {
            print!("Polynomial degree exceeds expected degree");
            return false;
        }

        // 最初のクエリ点セットを Fiat-Shamir で取得
        let top_indices = match self.sample_indices(
            proof_stream.verifier_fiat_shamir(32),
            (self.domain_length >> 1) as usize,
            (self.domain_length >> (self.num_rounds() - 1)) as usize,
            self.num_colinearity_tests,
        ) {
            Ok(indices) => indices,
            Err(_) => return false,
        };

        // 各ラウンドでの線形性チェックとマークル証明の検証
        for r in 0..(self.num_rounds() - 1) as usize {
            println!("round {}, domain_length >> (r+1) = {}", r, self.domain_length >> (r + 1));
            let c_indices: Vec<u128> = top_indices.iter().map(|i| i % (self.domain_length >> (r + 1))).collect();
            let a_indices = c_indices.clone();
            let b_indices: Vec<u128> = a_indices.iter().map(|i| i + (self.domain_length >> (r + 1))).collect();
            println!("c_indices: {:?}", c_indices);
            println!("a_indices: {:?}", a_indices);
            println!("b_indices: {:?}", b_indices);

            let mut aa = vec![];
            let mut bb = vec![];
            let mut cc = vec![];

            for s in 0..self.num_colinearity_tests {
                let tuple = proof_stream.pull::<Vec<FieldElement>>();
                let (ay, by, cy) = (tuple[0], tuple[1], tuple[2]);
                aa.push(ay);
                bb.push(by);
                cc.push(cy);

                if r == 0 {
                    polynomial_values.push((a_indices[s], ay));
                    polynomial_values.push((b_indices[s], by));
                }

                let ax = &offset * &omega.pow(a_indices[s]);
                let bx = &offset * &omega.pow(b_indices[s]);
                let cx = alphas[r];

                if !Self::test_colinearity(vec![vec![ax, ay], vec![bx, by], vec![cx, cy]]) {
                    print!("Colinearity test failed for round {}", r);
                    return false;
                }
            }

            println!("Round {}: Colinearity test passed", r);
            for i in 0..self.num_colinearity_tests {
                let path = proof_stream.pull::<Vec<Vec<u8>>>();
                let leaf = aa[i].value.to_be_bytes().to_vec();
                if !Merkle::new().blake_verify(roots[r].clone(), a_indices[i] as usize, &path, leaf.clone()) {
                    print!("Merkle proof verification failed for a_indices at round {}", r);
                    return false;
                }
                let path = proof_stream.pull::<Vec<Vec<u8>>>();
                let leaf = bb[i].value.to_be_bytes().to_vec();
                if !Merkle::new().blake_verify(roots[r].clone(), b_indices[i] as usize, &path, leaf.clone()) {
                    print!("Merkle proof verification failed for b_indices at round {}", r);
                    return false;
                }
                let path = proof_stream.pull::<Vec<Vec<u8>>>();
                let leaf = cc[i].value.to_be_bytes().to_vec();
                if !Merkle::new().blake_verify(roots[r + 1].clone(), c_indices[i] as usize, &path, leaf) {
                    print!("Merkle proof verification failed for c_indices at round {}", r);
                    return false;
                }
            }

            omega = &omega * &omega;
            offset = &offset * &offset;
        }
        true
    }
}

// tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proofstream::ProofStream;
    use crate::modulus::{Field, FieldElement};
    use std::collections::HashSet;

    #[test]
    fn test_sample_indices_validity_and_uniqueness() {
        let field = Field::new(340282366920938463463374557953744961537);
        let offset = FieldElement::new(1, field.clone());
        let omega = Field::generator(field.clone());

        let fri = Fri::new(offset, omega, 64, 2, 4);
        let seed = vec![42u8; 32]; // 任意のFiat-Shamirシード

        let size = 64;
        let reduced_size = 32;
        let number = 8;

        let indices_result = fri.sample_indices(seed.clone(), size, reduced_size, number);
        assert!(indices_result.is_ok());

        let indices = indices_result.unwrap();

        // 1. 要素数が正しい
        assert_eq!(indices.len(), number);

        // 2. 範囲チェック
        for &idx in &indices {
            assert!(idx < size as u128);
        }

        // 3. reduced_index の一意性チェック
        let reduced: Vec<u128> = indices.iter().map(|i| i % (reduced_size as u128)).collect();
        let mut reduced_sorted = reduced.clone();
        reduced_sorted.sort();
        reduced_sorted.dedup();

        assert_eq!(reduced.len(), reduced_sorted.len());
    }

    #[test]
    fn test_sample_indices_determinism() {
        let field = Field::new(340282366920938463463374557953744961537);
        let offset = FieldElement::new(1, field.clone());
        let omega = FieldElement::new(2, field.clone());

        let fri = Fri::new(offset, omega, 64, 2, 4);
        let seed = vec![99u8; 32];

        let result1 = fri.sample_indices(seed.clone(), 64, 32, 8).unwrap();
        let result2 = fri.sample_indices(seed.clone(), 64, 32, 8).unwrap();

        assert_eq!(result1, result2); // 同じシードなら出力も同じ
    }

    #[test]
    fn test_sample_indices_error_conditions() {
        let field = Field::new(40282366920938463463374557953744961537);
        let offset = FieldElement::new(1, field.clone());
        let omega = Field::generator(field.clone());
        let fri = Fri::new(offset, omega, 64, 2, 4);

        // number > reduced_size → エラー
        let result = fri.sample_indices(vec![1, 2, 3], 16, 4, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("available"));

        // number > 2 * reduced_size → エラー
        let result = fri.sample_indices(vec![1, 2, 3], 64, 8, 17);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "cannot sample more indices than available in last codeword; requested: 17, available: 8"
        );
    }
    #[test]
    fn test_codewords() {
        let field = Field::new(340282366920938463463374557953744961537);
        let offset = FieldElement::new(3, field.clone());
        let omega = FieldElement::new(246301224039257635126066389490736973866, field.clone());
        let domain_length = 1024;
        let expansion_factor = 8;
        let num_colinearity_tests = 27;
        let fri = Fri::new(offset, omega, domain_length, expansion_factor, num_colinearity_tests);

        // 32次多項式
        let poly = Polynomial::new(vec![
            FieldElement::new(1, field.clone()),
            FieldElement::new(2, field.clone()),
            FieldElement::new(3, field.clone()),
            FieldElement::new(4, field.clone()),
            FieldElement::new(5, field.clone()), // ← x^2項
            FieldElement::new(6, field.clone()),
            FieldElement::new(7, field.clone()),
            FieldElement::new(8, field.clone()), // ← x^2項
            FieldElement::new(9, field.clone()),
            FieldElement::new(10, field.clone()),
            FieldElement::new(11, field.clone()),
            FieldElement::new(12, field.clone()),
            FieldElement::new(13, field.clone()),
            FieldElement::new(14, field.clone()),
            FieldElement::new(15, field.clone()),
            FieldElement::new(16, field.clone()),
            FieldElement::new(17, field.clone()),
            FieldElement::new(18, field.clone()),
            FieldElement::new(19, field.clone()),
            FieldElement::new(20, field.clone()),
            FieldElement::new(21, field.clone()),
            FieldElement::new(22, field.clone()),
            FieldElement::new(23, field.clone()),
            FieldElement::new(24, field.clone()),
            FieldElement::new(25, field.clone()),
            FieldElement::new(26, field.clone()),
            FieldElement::new(27, field.clone()),
            FieldElement::new(28, field.clone()),
            FieldElement::new(29, field.clone()),
            FieldElement::new(30, field.clone()),
            FieldElement::new(31, field.clone()),
            FieldElement::new(32, field.clone()),
        ]);

        let domain: Vec<FieldElement> = fri.eval_domain();
        let mut seen = HashSet::new();
        for (i, x) in domain.iter().enumerate() {
            if !seen.insert(x.value) {
                println!("❌ Duplicate found in domain at index {}: value = {}", i, x.value);
            }
        }

        let codeword = poly.evaluate_domain(&domain);
        let mut proof_stream = ProofStream::new();
        let codewords = fri.commit(codeword.clone(), &mut proof_stream);
        let mut roots = vec![];
        //let prove_result = fri.prove(codeword.clone(), &mut proof_stream);
        for _ in 0..fri.num_rounds() {
            roots.push(proof_stream.pull::<Vec<u8>>());
        }
        let last_stream = proof_stream.pull::<Vec<FieldElement>>();
        
        let last_codeword = codewords.last().unwrap();
        assert_eq!(last_codeword, &last_stream, "Last codeword does not match expected value");
        let mut last_omega = omega;
        let mut last_offset = offset;
        for _ in 0..(fri.num_rounds()-1) {
            last_omega = &last_omega * &last_omega;
            last_offset = &last_offset * &last_offset;
        }
        println!("test_omega={:?}, {:?}", last_omega, last_offset);
        let last_domain: Vec<FieldElement> = (0..last_codeword.len())
            .map(|i| &last_offset * &last_omega.pow(i as u128))
            .collect();

        let mut seen = HashSet::new();
        for (i, x) in last_codeword.iter().enumerate() {
            if !seen.insert(x.value) {
                println!("❌ Duplicate found in domain at index {}: value = {}", i, x.value);
            }
        }
        let a: &[FieldElement] = &last_codeword[0..3];
        let b: &[FieldElement] = &last_domain[0..3];  
        println!("last_domain: {:?}", a);
        println!("last_codeword: {:?}", b);
        assert_eq!(last_domain.len() as u128, last_codeword.len() as u128, "Last domain length does not match last codeword length");
        let poly = Polynomial::interpolate_domain(&last_domain, &last_codeword);
        for i in 0..(last_codeword.len()) {
            let v1 = &last_codeword[i];
            let v2 = poly.evaluate(&last_domain[i]);
            if v1 != &v2 {
                println!("❌ mismatch at {}: expected {}, got {}", i, v1.value, v2.value);
                assert_eq!(v1, &v2, "Polynomial evaluation mismatch at index {}", i);
            }
        }
        
    }
    #[test]
    fn test_prove_and_verify_success() {
        let field = Field::new(340282366920938463463374557953744961537);
        let offset = FieldElement::new(5, field.clone());
        let omega = FieldElement::new(246301224039257635126066389490736973866, field.clone());
        let domain_length = 1024;
        let expansion_factor = 8;
        let num_colinearity_tests = 27;

        let fri = Fri::new(offset, omega, domain_length, expansion_factor, num_colinearity_tests);

        // 32次多項式
        let poly = Polynomial::new(vec![
            FieldElement::new(1, field.clone()),
            FieldElement::new(2, field.clone()),
            FieldElement::new(3, field.clone()),
            FieldElement::new(4, field.clone()),
            FieldElement::new(5, field.clone()), // ← x^2項
            FieldElement::new(6, field.clone()),
            FieldElement::new(7, field.clone()),
            FieldElement::new(8, field.clone()), // ← x^2項
            FieldElement::new(9, field.clone()),
            FieldElement::new(10, field.clone()),
            FieldElement::new(11, field.clone()),
            FieldElement::new(12, field.clone()),
            FieldElement::new(13, field.clone()),
            FieldElement::new(14, field.clone()),
            FieldElement::new(15, field.clone()),
            FieldElement::new(16, field.clone()),
            FieldElement::new(17, field.clone()),
            FieldElement::new(18, field.clone()),
            FieldElement::new(19, field.clone()),
            FieldElement::new(20, field.clone()),
            FieldElement::new(21, field.clone()),
            FieldElement::new(22, field.clone()),
            FieldElement::new(23, field.clone()),
            FieldElement::new(24, field.clone()),
            FieldElement::new(25, field.clone()),
            FieldElement::new(26, field.clone()),
            FieldElement::new(27, field.clone()),
            FieldElement::new(28, field.clone()),
            FieldElement::new(29, field.clone()),
            FieldElement::new(30, field.clone()),
            FieldElement::new(31, field.clone()),
            FieldElement::new(32, field.clone()),
        ]);

        let domain: Vec<FieldElement> = (0..domain_length)
            .map(|i| &offset.clone() * &omega.pow(i as u128))
            .collect();

        // ドメインの重複チェック
        let mut seen = HashSet::new();
        for (i, x) in domain.iter().enumerate() {
            if !seen.insert(x.value) {
                println!("❌ Duplicate found in domain at index {}: value = {}", i, x.value);
            }
        }

        let codeword = poly.evaluate_domain(&domain);
        assert_eq!(codeword.len() as u128, domain_length);

        let mut proof_stream = ProofStream::new();
        let prove_result = fri.prove(codeword.clone(), &mut proof_stream);
        
        assert!(prove_result.is_ok());
        assert_eq!(prove_result.as_ref().unwrap().len(), num_colinearity_tests);

        let mut poly_vals = vec![];
        let is_valid = fri.verify(&mut proof_stream, &mut poly_vals);
        print!("{}", is_valid);
        assert!(is_valid, "FRI verify failed unexpectedly");
    }
}