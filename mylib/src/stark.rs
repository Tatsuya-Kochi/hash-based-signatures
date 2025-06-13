use rand::RngCore;
use crate::modulus::{self, FieldElement};
use modulus::Field as Field;
use crate::merkle::Merkle;
use crate::proofstream::ProofStream;
use crate::polynomial::Polynomial;
use crate::mpolynomial::MPolynomial;
use crate::fri::Fri;
use std::collections::HashSet;

pub struct Stark {
    pub field: Field,
    pub expansion_factor: usize,
    pub num_colinearity_checks: usize,
    pub security_level: usize,
    pub num_registers: usize,
    pub original_trace_length: usize,
    pub num_randomizers: usize,
    pub generator: FieldElement,
    pub omega: FieldElement,
    pub omicron: FieldElement,
    pub omicron_domain: Vec<FieldElement>,
    pub fri: Fri,
}

impl Stark {
    pub fn new(
        field: Field,
        expansion_factor: usize,
        num_colinearity_checks: usize,
        security_level: usize,
        num_registers: usize,
        num_cycles: usize,
        transition_constraints_degree: usize,
    ) -> Self {
        assert!(field.p.ilog2() as usize + 1 >= security_level, "p must have at least as many bits as security level");
        assert!(expansion_factor.is_power_of_two(), "expansion factor must be a power of 2");
        assert!(expansion_factor >= 4, "expansion factor must be 4 or greater");
        //assert!(num_colinearity_checks * 2 >= security_level, "number of colinearity checks must be at least half of security level");

        let num_randomizers = 4 * num_colinearity_checks;
        let original_trace_length = num_cycles;
        let randomized_trace_length = original_trace_length + num_randomizers;
        let omicron_domain_length = 1 << ((randomized_trace_length * transition_constraints_degree).next_power_of_two().trailing_zeros());
        let fri_domain_length = omicron_domain_length * expansion_factor;

        let generator = field.generator();
        let omega = field.primitive_nth_root(fri_domain_length as u128);
        let omicron = field.primitive_nth_root(omicron_domain_length as u128);
        let omicron_domain: Vec<FieldElement> = (0..omicron_domain_length)
            .map(|i| omicron.pow(i as u128))
            .collect();

        let fri = Fri::new(generator, omega, fri_domain_length as u128, expansion_factor, num_colinearity_checks);

        Stark {
            field,
            expansion_factor,
            num_colinearity_checks,
            security_level,
            num_registers,
            original_trace_length,
            num_randomizers,
            generator,
            omega,
            omicron,
            omicron_domain,
            fri,
        }
    }

    pub fn transition_zerofier(&self) -> Polynomial {
        let domain = &self.omicron_domain[..(self.original_trace_length - 1)];
        Polynomial::zerofier_domain(domain)
    }

    // boundary:境界制約 Vec<(usize, usize, FieldElement)>
    // 各要素は (c, r, v) で、c はサイクル数、r はレジスタ番号、v は値
    pub fn boundary_zerofiers(&self, boundary: &Vec<(usize, usize, FieldElement)>) -> Vec<Polynomial> {
        let mut zerofiers = Vec::new();
        for s in 0..self.num_registers {
            let points: Vec<FieldElement> = boundary
                .iter()
                .filter(|(_, r, _)| *r == s)
                .map(|(c, _, _)| self.omicron.pow(*c as u128))
                .collect();
            // 境界制約のないレジスタはスキップ
            if points.is_empty() {
                continue;
            }
            zerofiers.push(Polynomial::zerofier_domain(&points));
        }
        zerofiers
    }

    // boundary:境界制約 Vec<(usize, usize, FieldElement)>
    // 各要素は (c, r, v) で、c はサイクル数、r はレジスタ番号、v は値
    // 境界制約に基づいて境界多項式を生成
    pub fn boundary_interpolants(&self, boundary: &Vec<(usize, usize, FieldElement)>) -> Vec<Polynomial> {
        let mut interpolants = Vec::new();
        for s in 0..self.num_registers {
            let points: Vec<(FieldElement, FieldElement)> = boundary
                .iter()
                .filter(|(_, r, _)| *r == s)
                .map(|(c, _, v)| (self.omicron.pow(*c as u128), *v))
                .collect();
            // 境界制約のないレジスタはスキップ
            if points.is_empty() {
                continue;
            }
            let (domain, values): (Vec<_>, Vec<_>) = points.into_iter().unzip();
            interpolants.push(Polynomial::interpolate_domain(&domain, &values));
        }
        interpolants
    }

    // 境界制約に基づいて境界商多項式の次数を計算 
    pub fn boundary_quotient_degree_bounds(&self, randomized_trace_length: usize, boundary: &Vec<(usize, usize, FieldElement)>) -> Vec<usize> {
        let randomized_trace_degree = randomized_trace_length - 1;
        self.boundary_zerofiers(boundary)
            .iter()
            .map(|bz| randomized_trace_degree - bz.degree() as usize)
            .collect()
    }

    // ランダムな重みをnumberの数生成 randomness：seed値
    pub fn sample_weights(&self, number: usize, randomness: Vec<u8>) -> Vec<FieldElement> {
        (0..number)
            .map(|i| {
                let mut data = randomness.clone();
                data.extend_from_slice(&(i as u64).to_be_bytes());
                self.field.sample(data)
            })
            .collect()
    }

    /*
    指定された制約に対応する quotient 多項式の中で、最も高い次数は何か？」
    「それを補間するためにはどのくらいの FFT ドメイン（2のべきサイズ）が必要か？」
    「そのドメインで補間できる最大次数は何か？」
    */
    fn max_degree(&self, transition_constraints: &Vec<MPolynomial>) -> usize {
        let d_bounds = self.transition_quotient_degree_bounds(transition_constraints);
        let max = *d_bounds.iter().max().unwrap_or(&0);
        (1 << (max.next_power_of_two().trailing_zeros())) - 1
    }

    // 遷移制約（transition constraints）」の quotient 多項式の次数上限を返す
    fn transition_quotient_degree_bounds(&self, transition_constraints: &Vec<MPolynomial>) -> Vec<usize> {
        transition_constraints.iter().map(|_| self.original_trace_length).collect()
    }
    
    pub fn prove(&self, trace: &mut Vec<Vec<FieldElement>>, transition_constraints: &Vec<MPolynomial>, boundary: &Vec<(usize, usize, FieldElement)>, proof_stream: &mut ProofStream) -> Vec<u8> {
        // トレースにランダム行を追加
        for _ in 0..self.num_randomizers {
            let row: Vec<FieldElement> = (0..self.num_registers)
                .map(|_| {
                    let mut bytes = [0u8; 17];
                    rand::thread_rng().fill_bytes(&mut bytes);
                    self.field.sample(bytes.to_vec())
                })
                .collect();
            trace.push(row);
        }

        // 生成元からトレースドメインを生成
        let trace_domain: Vec<FieldElement> = (0..trace.len())
            .map(|i| self.omicron.pow(i as u128))
            .collect();

        // トレース多項式を生成
        let trace_polynomials: Vec<Polynomial> = (0..self.num_registers)
            .map(|s| {
                // 各レジスタのトレースを抽出
                let single_trace: Vec<FieldElement> = trace.iter().map(|row| row[s]).collect();
                Polynomial::interpolate_domain(&trace_domain, &single_trace)
            })
            .collect();

        // 境界制約
        // P(x) 境界制約の多項式
        let boundary_interpolants = self.boundary_interpolants(boundary);
        // Z(x) 分母
        let boundary_zerofiers = self.boundary_zerofiers(boundary);
        // Q(x) 評価値
        let constrained_registers: HashSet<usize> = boundary.iter().map(|&(_, r, _)| r).collect();
        let boundary_quotients: Vec<Polynomial> = (0..self.num_registers)
        .map(|s| {
            if constrained_registers.contains(&s) {
                &(&trace_polynomials[s] - &boundary_interpolants[s]) / &boundary_zerofiers[s]
            } else {
                Polynomial::new(vec![])  // ゼロ多項式などの無害な代替
            }
        })
        .collect();

        let fri_domain = self.fri.eval_domain();
        let fri_domain: &[FieldElement] = &fri_domain; // 型合わせ
            
        // 各Q(x)をFRIドメインで評価
        let boundary_quotient_codewords: Vec<Vec<FieldElement>> = boundary_quotients
            .iter()
            .map(|q| q.evaluate_domain(fri_domain))
            .collect();

        // Q(x)の評価値からMerkleルートを生成
        for bqc in &boundary_quotient_codewords {
            let root = Merkle::new().blake_commit(&crate::merkle::prepare_data(&bqc));
            proof_stream.push(&root);
        }

        // x
        let mut point: Vec<Polynomial> = vec![Polynomial::new(vec![self.field.zero(), self.field.one()])];
        // 現在のステップ f_i(x)
        point.extend(trace_polynomials.clone());
        // 次のステップ f_{i}(wx)
        point.extend(trace_polynomials.iter().map(|tp| tp.scale(&self.omicron)));

        // P(x)
        let transition_polynomials: Vec<Polynomial> = transition_constraints
            .iter()
            .map(|tc| tc.evaluate_symbolic(&point))
            .collect();

        // Q(x)
        let transition_quotients: Vec<Polynomial> = transition_polynomials
            .iter()
            .map(|tp| tp / &self.transition_zerofier())
            .collect();

        // 遷移制約の最大次数
        let max_deg = self.max_degree(transition_constraints);
        // 次数max_degのランダムな多項式を生成
        let randomizer_poly = Polynomial::new(
            (0..=max_deg)
                .map(|_| {
                    let mut bytes = [0u8; 17];
                    rand::thread_rng().fill_bytes(&mut bytes);
                    self.field.sample(bytes.to_vec())
                })
                .collect()
        );
        // ランダムな多項式をFRIドメインで評価し、Merkleルートを証明ストリームに追加
        let randomizer_codeword = randomizer_poly.evaluate_domain(fri_domain);
        let randomizer_root = Merkle::new().blake_commit(&crate::merkle::prepare_data(&randomizer_codeword));
        proof_stream.push(&randomizer_root);

        // ランダムな重みを生成
        let weights = self.sample_weights(
            1 + 2 * transition_quotients.len() + 2 * boundary_quotients.len(),
            proof_stream.prover_fiat_shamir(32),
        );

        let x = Polynomial::new(vec![self.field.zero(), self.field.one()]);
        let mut terms: Vec<Polynomial> = vec![randomizer_poly];

        // 遷移制約の商多項式
        for (i, tq) in transition_quotients.iter().enumerate() {
            // 差分を shift とすることで、各多項式を高次数方向に調整
            let shift = max_deg - self.transition_quotient_degree_bounds(transition_constraints)[i];
            terms.push(tq.clone());
            terms.push(&x.clone().pow(shift as u128) * tq);
        }
        // 境界制約の商多項式
        for (i, bq) in boundary_quotients.iter().enumerate() {
            let shift = max_deg - self.boundary_quotient_degree_bounds(trace.len(), boundary)[i];
            terms.push(bq.clone());
            terms.push(&x.clone().pow(shift as u128) * bq);
        }

        // ランダム線形結合 
        let combination = terms
            .iter()
            .zip(weights.iter())
            .map(|(term, weight)| &term.clone() * &Polynomial::new(vec![*weight]))
            .reduce(|a, b| &a + &b)
            .unwrap_or_else(|| Polynomial::new(vec![]));

        // Friドメイン上で評価して、FRI 証明を生成
        let combined_codeword = combination.evaluate_domain(fri_domain);
        let indices = self.fri.prove(combined_codeword, proof_stream).unwrap(); // codewordsが返る

        // FRI用のインデックスを拡張 f(i) と f(i + expansion_factor)でFRIの折り畳みが成り立つか検証
        let duplicated_indices: Vec<u128> = indices.iter()
            .flat_map(|&i| vec![i, (i + self.expansion_factor as u128) % self.fri.domain_length])
            .collect();

        // 境界商コードワードの認証情報（値 + Merkleパス）を記録
        for bqc in &boundary_quotient_codewords {
            for &i in &duplicated_indices {
                proof_stream.push(&[bqc[i as usize]]);
                let path = Merkle::new().blake_open(i as usize, &crate::merkle::prepare_data(&bqc));
                proof_stream.push(&path);
            }
        }

        // ランダム化された商コードワードの認証情報（値 + Merkleパス）を記録
        for &i in &indices {
            proof_stream.push(&[randomizer_codeword[i as usize]]);
            let path = Merkle::new().blake_open(i as usize, &crate::merkle::prepare_data(&randomizer_codeword));
            proof_stream.push(&path);
        }

        proof_stream.serialize()
    }

    pub fn verify(&self, transition_constraints: &Vec<MPolynomial>, boundary: &Vec<(usize, usize, FieldElement)>, proof_stream: &mut ProofStream) -> bool {
        // 最終ステップに境界制約がある前提
        let original_trace_length = 1 + boundary.iter().map(|(c, _, _)| *c).max().unwrap_or(0);
        let randomized_trace_length = original_trace_length + self.num_randomizers;

        // 境界商多項式のマークルルート
        let boundary_quotient_roots: Vec<Vec<u8>> = (0..self.num_registers).map(|_| proof_stream.pull()).collect();
        // ランダム多項式のマークルルート
        let randomizer_root: Vec<u8> = proof_stream.pull();

        let weights = self.sample_weights(
            1 + 2 * transition_constraints.len() + 2 * self.boundary_interpolants(boundary).len(),
            proof_stream.verifier_fiat_shamir(32),
        );

        // FRI証明の検証
        let mut polynomial_values = Vec::new();
        // FRIの評価点を受け取る
        let verifier_accepts = self.fri.verify(proof_stream, &mut polynomial_values);
        if !verifier_accepts {
            return false;
        }

        polynomial_values.sort_by_key(|(i, _)| *i);
        let indices: Vec<u128> = polynomial_values.iter().map(|(i, _)| *i).collect();
        let values: Vec<FieldElement> = polynomial_values.iter().map(|(_, v)| *v).collect();

        // FRIのインデックスを拡張 f(i) と f(i + expansion_factor)でFRIの折り畳みが成り立つか検証
        let duplicated_indices: Vec<u128> = indices.iter().flat_map(|&i| vec![i, (i + self.expansion_factor as u128) % self.fri.domain_length]).collect();

        // 境界商の Merkle 認証（値＋パス）を検証しながら格納
        let mut leafs: Vec<_> = (0..self.num_registers).map(|_| std::collections::HashMap::new()).collect();
        for r in 0..self.num_registers {
            for &i in &duplicated_indices {
                let value: FieldElement = proof_stream.pull();
                let path: Vec<Vec<u8>> = proof_stream.pull();
                if !Merkle::new().blake_verify(boundary_quotient_roots[r].clone(), i as usize, &path, value.value.to_be_bytes().to_vec()) {
                    return false;
                }
                leafs[r].insert(i, value);
            }
        }

        // ランダム化された商の Merkle 認証（値＋パス）を検証しながら格納
        let mut randomizer = std::collections::HashMap::new();
        for &i in &indices {
            let value: FieldElement = proof_stream.pull();
            let path: Vec<Vec<u8>> = proof_stream.pull();
            if !Merkle::new().blake_verify(randomizer_root.clone(), i as usize, &path, value.value.to_be_bytes().to_vec()) {
                return false;
            }
            randomizer.insert(i, value);
        }

        // 各インデックスで「線形結合値」と「FRI値」を照合
        for (i_idx, &i) in indices.iter().enumerate() {
            let domain_current_index = &self.generator * &self.omega.pow(i);
            let next_index = (i + self.expansion_factor as u128) % self.fri.domain_length;
            let domain_next_index = &self.generator * &self.omega.pow(next_index);

            let mut current_trace = vec![self.field.zero(); self.num_registers];
            let mut next_trace = vec![self.field.zero(); self.num_registers];

            let boundary_zerofiers = self.boundary_zerofiers(boundary);
            let boundary_interpolants = self.boundary_interpolants(boundary);

            for s in 0..self.num_registers {
                let zerofier = &boundary_zerofiers[s];
                let interpolant = &boundary_interpolants[s];
                // トレースの復元
                current_trace[s] = &(&leafs[s][&i] * &zerofier.evaluate(&domain_current_index)) + &interpolant.evaluate(&domain_current_index);
                next_trace[s] = &(&leafs[s][&next_index] * &zerofier.evaluate(&domain_next_index)) + &interpolant.evaluate(&domain_next_index);
            }

            // 遷移制約の評価
            let mut point = vec![domain_current_index];
            point.extend(current_trace.clone());
            point.extend(next_trace);

            let transition_values: Vec<FieldElement> = transition_constraints.iter().map(|tc| tc.evaluate(&point)).collect();

            let mut terms = vec![randomizer[&i]];
            for (s, tcv) in transition_values.iter().enumerate() {
                let quotient = tcv / &self.transition_zerofier().evaluate(&domain_current_index);
                let shift = self.max_degree(transition_constraints) - self.transition_quotient_degree_bounds(transition_constraints)[s];
                terms.push(quotient);
                terms.push(&quotient * &domain_current_index.pow(shift as u128));
            }
            for s in 0..self.num_registers {
                let bqv = leafs[s][&i];
                let shift = self.max_degree(transition_constraints) - self.boundary_quotient_degree_bounds(randomized_trace_length, boundary)[s];
                terms.push(bqv);
                terms.push(&bqv * &domain_current_index.pow(shift as u128));
            }

            // FRI によって検証された「ランダム線形結合多項式の評価値と実際のFRI評価値を比較
            let expected = values[i_idx];
            let actual = terms.iter().zip(weights.iter()).fold(self.field.zero(), |acc, (t, w)| &acc + &(w * t));
            if expected != actual {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modulus::Field;
    use crate::mpolynomial::MPolynomial;

    #[test]
    fn test_boundary_zerofiers() {
        let field = Field::new(340282366920938463463374557953744961537); 
        let stark = Stark::new(
            field,
            8,     // expansion_factor
            48,     // num_colinearity_checks
            96,    // security_level
            22,    // num_registers
            1024,  // num_cycles (original_trace_length)
            6      // transition_constraints_degree
        );
        print!("{:?}", stark.omicron);
        let boundary = vec![(0, 0, FieldElement::new(1, field)), (1023, 1, FieldElement::new(2, field))];
        let zerofiers = stark.boundary_zerofiers(&boundary);
        assert_eq!(zerofiers.len(), boundary.len());
    }
    #[test]
    fn test_boundary_interpolants() {
        let field = Field::new(340282366920938463463374557953744961537); 
        let stark = Stark::new(
            field,
            8,     // expansion_factor
            48,     // num_colinearity_checks
            96,    // security_level
            22,    // num_registers
            1024,  // num_cycles (original_trace_length)
            6      // transition_constraints_degree
        );
        let boundary = vec![(0, 0, FieldElement::new(1, field)), (1023, 1, FieldElement::new(2, field))];
        let interpolants = stark.boundary_interpolants(&boundary);
        assert_eq!(interpolants.len(), boundary.len());
    }
}