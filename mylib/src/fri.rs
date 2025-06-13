use blake3;
use crate::modulus::{self, FieldElement};
use modulus::Field as Field;
use crate::merkle;
use merkle::Merkle;
use crate::proofstream;
use proofstream::ProofStream;
use crate::polynomial;
use polynomial::Polynomial;

pub struct Fri {
    offset: FieldElement, // starkのfield.generatorで生成 生成元
    omega: FieldElement,  // starkのprimitive_nth_root(fri_domain_length)で生成 原始根
    domain_length: u128, // starkのfri_domainに対応
    field: Field,
    expansion_factor: usize,
    num_colinearity_tests: usize, // starkのnum_colinearity_checksに対応
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

    // FRIのラウンド数を計算
    pub fn num_rounds(&self) -> u128 {
        let mut codeword_length = self.domain_length;
        let mut num_rounds = 0;
        while codeword_length > self.expansion_factor as u128 && (4 * self.num_colinearity_tests as u128) < codeword_length {
            codeword_length /= 2;
            num_rounds += 1;
        }
        num_rounds
    }

    // offset*omega^iをドメインの長さだけ繰り返す
    pub fn eval_domain(&self) -> Vec<FieldElement> {
        (0..self.domain_length)
            .map(|i| self.offset * self.omega.pow(i as u128))
            .collect()
    }
    // コードワードはPolynomialクラスのcoefficient
    pub fn prove(&self, codeword: Vec<FieldElement>, proof_stream: &mut ProofStream) -> Result<Vec<u128>, String> {
        if self.domain_length != codeword.len() as u128 {
            return Err("initial codeword length does not match length of initial codeword".to_string());
        }

        // commit phase
        let codewords = self.commit(codeword, proof_stream);

        // num_colinearity_testsの数のランダムなインデックス値を生成
        let top_level_indices = self.sample_indices(
            proof_stream.prover_fiat_shamir(32), //shake_256(self.serialize()).digest(num_bytes)
            codewords[1].len(),
            codewords[codewords.len() - 1].len(),
            self.num_colinearity_tests,
        );

        // エラーハンドリング
        let mut indices = match top_level_indices.clone() {
            Ok(v) => v,
            Err(e) => {
                println!("err value = {}", e);
                return Err(e); // エラーが発生した場合に関数からリターン
            }
        };

        // query phase
        for i in 0..(codewords.len() - 1) {
            indices = indices.iter().map(|&index| index % ((codewords[i].len() / 2))as u128).collect();
            self.query(&codewords[i], &codewords[i + 1], &indices, proof_stream);
        }

        top_level_indices
    }

    
    pub fn commit(&self, mut codeword: Vec<FieldElement>, proof_stream: &mut ProofStream) -> Vec<Vec<FieldElement>> {
        let one = self.field.one();
        let two = FieldElement::new(2, self.field);
        let mut omega = self.omega;
        let mut offset = self.offset;
        let mut codewords = vec![];

        // コードワードをマークルツリーにコミット
        for r in 0..self.num_rounds() {
            // compute and send Merkle root
            let merkle = Merkle::new(); // 要改善
            let root = Merkle::blake_commit(&merkle, merkle::prepare_data(codeword.clone()));
            proof_stream.push(&root);

            // prepare next round, if necessary
            if r == self.num_rounds() - 1 {
                break;
            }

            // get challenge
            let alpha = self.field.sample(proof_stream.prover_fiat_shamir(32));

            // collect codeword
            codewords.push(codeword.clone());

            // split and fold
            codeword = (0..(codeword.len() / 2))
                .map(|i| {
                    let omega_i = omega.pow(i as u128);
                    let term1 = one + alpha / (offset * omega_i);
                    let term2 = one - alpha / (offset * omega_i);
                    two.inverse() * (term1 * codeword[i] + term2 * codeword[codeword.len() / 2 + i])
                })
                .collect();

            omega = omega.pow(2);
            offset = offset.pow(2);
        }

        // send last codeword
        proof_stream.push(&codeword.clone());

        // collect last codeword too
        codewords.push(codeword);

        codewords
    }

    pub fn query(
        &self,
        current_codeword: &Vec<FieldElement>,
        next_codeword: &Vec<FieldElement>,
        c_indices: &Vec<u128>,
        proof_stream: &mut ProofStream,
    ) -> Vec<u128> {
        // infer a and b indices
        let a_indices: Vec<u128> = c_indices.clone();
        let b_indices: Vec<u128> = c_indices.iter().map(|&index| index + current_codeword.len() as u128 / 2).collect();

        // reveal leafs
        for s in 0..self.num_colinearity_tests {
            let s = s as usize;
            proof_stream.push(&vec![
                current_codeword[a_indices[s] as usize],
                current_codeword[b_indices[s] as usize],
                next_codeword[c_indices[s] as usize]])
        }

        let merkle = Merkle::new();
        // reveal authentication paths
        for s in 0..self.num_colinearity_tests {
            proof_stream.push(&Merkle::blake_open(&merkle, a_indices[s] as usize, current_codeword.clone()));
            proof_stream.push(&Merkle::blake_open(&merkle, b_indices[s] as usize, current_codeword.clone()));
            proof_stream.push(&Merkle::blake_open(&merkle, c_indices[s] as usize, next_codeword.clone()));
        }

        let mut combined_indices = a_indices.clone();
        combined_indices.extend(b_indices);
        combined_indices
    }

    // Pythonの `sample_index` 関数に相当
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
            // Seed + counter を連結し、BLAKE2b ハッシュを計算
            let mut hasher = blake3::Hasher::new();
            hasher.update(&seed);
            hasher.update(&counter.to_le_bytes());  // counterをバイト列に変換
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

    pub fn verify(
        &self,
        proof_stream: &mut ProofStream,
        mut polynomial_values: Vec<(u128, FieldElement)>,
    ) -> bool {
        let mut omega = self.omega;
        let mut offset = self.offset;

        // Extract all roots and alphas
        let mut roots = Vec::new();
        let mut alphas = Vec::new();
        for _ in 0..self.num_rounds() {
            roots.push(proof_stream.pull::<Vec<u8>>());
            alphas.push(self.field.sample(proof_stream.verifier_fiat_shamir(32)));
        }

        // Extract last codeword
        let last_codeword: Vec<FieldElement> = proof_stream.pull();

        // Check if last codeword matches the given root
        let mut merkle = Merkle::new();
        if Merkle::blake_commit(&merkle, merkle::prepare_data(last_codeword.clone())) != *roots.last().unwrap() {
            println!("last codeword is not well formed");
            return false;
        }

        // Check if the last codeword is low degree
        let degree = (last_codeword.len() / self.expansion_factor) - 1;
        let mut last_omega = omega;
        let mut last_offset = offset;

        for _ in 0..self.num_rounds() - 1 {
            last_omega = last_omega^2;
            last_offset = last_offset^2;
        }

        // Assert that last_omega has the right order
        assert!(
            last_omega.inverse() == last_omega.pow(last_codeword.len() as u128 - 1),
            "omega does not have the right order"
        );

        // Compute interpolant
        let last_domain: Vec<FieldElement> = (0..last_codeword.len())
            .map(|i| last_offset * last_omega.pow(i as u128))
            .collect();
        let poly = Polynomial::interpolate_domain(&last_domain, &last_codeword);

        assert!(
            poly.evaluate_domain(last_domain) == last_codeword,
            "re-evaluated codeword does not match original!"
        );

        if poly.degree() > degree as isize {
            println!("last codeword does not correspond to polynomial of low enough degree");
            println!("observed degree: {}", poly.degree());
            println!("but should be: {}", degree);
            return false;
        }

        // Get indices
        let top_level_indices = self.sample_indices(
            proof_stream.verifier_fiat_shamir(32),
            (self.domain_length >> 1) as usize,
            (self.domain_length >> (self.num_rounds() - 1)) as usize,
            self.num_colinearity_tests,
        );

        // For every round, check consistency of subsequent layers
        for r in 0..(self.num_rounds() - 1) {
            // Fold c indices
            let c_indices: Vec<u128> = match &top_level_indices{
                Ok(v) => v.iter()
                .map(|&index| index % (self.domain_length >> (r + 1)))
                .collect(),
                Err(e) => {
                println!("err value = {}", e);
                return false; // エラーが発生した場合に関数からリターン
            }
        };
                

            // Infer a and b indices
            let a_indices = c_indices.clone();
            let b_indices: Vec<u128> = a_indices
                .iter()
                .map(|&index| index + (self.domain_length >> (r + 1)))
                .collect();

            // Read values and check colinearity
            let mut aa = Vec::new();
            let mut bb = Vec::new();
            let mut cc = Vec::new();

            for s in 0..self.num_colinearity_tests {
                let (ay, by, cy): (FieldElement, FieldElement, FieldElement) =
                    proof_stream.pull();
                aa.push(ay);
                bb.push(by);
                cc.push(cy);

                // Record top-layer values for later verification
                if r == 0 {
                    polynomial_values.push((a_indices[s], ay));
                    polynomial_values.push((b_indices[s], by));
                }

                // Colinearity check
                let ax = offset * omega.pow(a_indices[s]);
                let bx = offset * omega.pow(b_indices[s]);
                let cx = alphas[r as usize];
                if !test_colinearity(vec![vec![ax, ay], vec![bx, by], vec![cx, cy]]) {
                    println!("colinearity check failure");
                    return false;
                }
            }

            // Verify authentication paths
            for i in 0..self.num_colinearity_tests {
                let path: Vec<Vec<u8>> = proof_stream.pull();
                if !Merkle::blake_verify(&mut merkle, roots[r as usize].clone(), a_indices[i], path, aa[i].value.to_string().into_bytes()) {
                    println!("merkle authentication path verification fails for aa");
                    return false;
                }

                let path: Vec<Vec<u8>> = proof_stream.pull();
                if !Merkle::blake_verify(&mut merkle, roots[r as usize].clone(), b_indices[i], path, bb[i].value.to_string().into_bytes()) {
                    println!("merkle authentication path verification fails for bb");
                    return false;
                }

                let path: Vec<Vec<u8>> = proof_stream.pull();
                if !Merkle::blake_verify(&mut merkle, roots[(r + 1) as usize].clone(), c_indices[i], path, cc[i].value.to_string().into_bytes()) {
                    println!("merkle authentication path verification fails for cc");
                    return false;
                }
            }

            // Square omega and offset to prepare for next round
            omega = omega^2;
            offset = offset^2;
        }

        // All checks passed
        true
    }
}

pub fn test_colinearity(points: Vec<Vec<FieldElement>>) -> bool {
    let domain: Vec<FieldElement> = points.iter().map(|p| p[0].clone()).collect();
    let values: Vec<FieldElement> = points.iter().map(|p| p[1].clone()).collect();
    let polynomial: Polynomial = Polynomial::interpolate_domain(&domain, &values);
    return polynomial.degree() == 1
}
