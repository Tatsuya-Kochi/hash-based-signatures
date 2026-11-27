use rand::RngCore;
use crate::modulus::{self, FieldElement};
use modulus::Field as Field;
use crate::merkle::Merkle;
use crate::proofstream::ProofStream;
use crate::polynomial::Polynomial;
use crate::mpolynomial::MPolynomial;
use crate::fri::Fri;
use std::collections::HashMap;

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
    pub trace_omicron: FieldElement,
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

        let num_randomizers = 0; // 互換のためフィールドは残すが 0 固定
        let original_trace_length = num_cycles;

        // omicron_domain_length は (original_trace_length * transition_constraints_degree) を2冪切り上げ
        let omicron_domain_length = 1 << (
            (original_trace_length * transition_constraints_degree)
                .next_power_of_two()
                .trailing_zeros()
        );
        let fri_domain_length = omicron_domain_length * expansion_factor;

        let generator = field.generator();
        let omega    = field.primitive_nth_root(fri_domain_length as u128);
        let omicron  = field.primitive_nth_root(omicron_domain_length as u128);

        assert!(original_trace_length > 0, "original_trace_length must be greater than 0");
        assert!(
            omicron_domain_length % original_trace_length == 0,
            "omicron domain length must be a multiple of the trace length"
        );
        let stride = omicron_domain_length / original_trace_length;
        let trace_omicron = omicron.pow(stride as u128); // 位数 = trace_len の根

        let omicron_domain: Vec<FieldElement> =
            (0..omicron_domain_length).map(|i| omicron.pow(i as u128)).collect();

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
            trace_omicron,
            omicron_domain,
            fri,
        }
    }

    fn trace_point_at(&self, step: usize) -> FieldElement {
        self.trace_omicron.pow(step as u128)
    }

    fn trace_domain_prefix(&self, length: usize) -> Vec<FieldElement> {
        let mut domain = Vec::with_capacity(length);
        let mut current = self.field.one();
        for _ in 0..length {
            domain.push(current);
            current = &current * &self.trace_omicron;
        }
        domain
    }

    pub fn transition_zerofier(&self) -> Polynomial {
        let domain = self.trace_domain_prefix(self.original_trace_length - 1);
        Polynomial::zerofier_domain(&domain)
    }

    // boundary:境界制約 Vec<(usize, usize, FieldElement)>
    // 各要素は (c, r, v) で、c はサイクル数、r はレジスタ番号、v は値
    pub fn boundary_zerofiers(&self, boundary: &Vec<(usize, usize, FieldElement)>) -> Vec<Polynomial> {
        let mut zerofiers = Vec::new();
        for s in 0..self.num_registers {
            let points: Vec<FieldElement> = boundary
                .iter()
                .filter(|(_, r, _)| *r == s)
                .map(|(c, _, _)| self.trace_point_at(*c))
                .collect();
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
                .map(|(c, _, v)| (self.trace_point_at(*c), *v))
                .collect();
            if points.is_empty() {
                continue;
            }
            let (domain, values): (Vec<_>, Vec<_>) = points.into_iter().unzip();
            interpolants.push(Polynomial::interpolate_domain(&domain, &values));
        }
        interpolants
    }

    // 境界制約に基づいて境界商多項式の次数を計算 
    pub fn boundary_quotient_degree_bounds(&self, trace_length: usize, boundary: &Vec<(usize, usize, FieldElement)>) -> Vec<usize> {
        let trace_degree = trace_length - 1;
        self.boundary_zerofiers(boundary)
            .iter()
            .map(|bz| trace_degree - bz.degree() as usize)
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

        // 生成元からトレースドメインを生成
        println!("Generating trace domain...");
        assert_eq!(
            trace.len(),
            self.original_trace_length,
            "trace length must equal original_trace_length"
        );
        let trace_domain = self.trace_domain_prefix(trace.len());
        println!("Trace domain length: {}", trace_domain.len());

        // トレース多項式を生成
        println!("Generating trace polynomials...");
        let trace_polynomials: Vec<Polynomial> = (0..self.num_registers)
            .map(|s| {
                // 各レジスタのトレースを抽出
                let single_trace: Vec<FieldElement> = trace.iter().map(|row| row[s]).collect();
                Polynomial::interpolate_domain_fft(&trace_domain, &single_trace)
            })
            .collect();

        // 境界制約
        // P(x) 境界制約の多項式
        print!("Generating boundary quotient polynomials...");
        let boundary_interpolants = self.boundary_interpolants(boundary);
        // Z(x) 分母
        let boundary_zerofiers = self.boundary_zerofiers(boundary);
        // Q(x) 評価値
        let mut constrained_list: Vec<usize> = boundary.iter().map(|&(_, r, _)| r).collect();
        constrained_list.sort_unstable();
        constrained_list.dedup();
        let register_to_index: HashMap<usize, usize> = constrained_list
            .iter()
            .enumerate()
            .map(|(idx, reg)| (*reg, idx))
            .collect();
        let boundary_quotients: Vec<Polynomial> = (0..self.num_registers)
            .map(|s| {
                if let Some(&idx) = register_to_index.get(&s) {
                    &(&trace_polynomials[s] - &boundary_interpolants[idx]) / &boundary_zerofiers[idx]
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
        let mut point: Vec<Polynomial> = vec![];
        // 現在のステップ f_i(x)
        point.extend(trace_polynomials.clone());
        // 次のステップ f_{i}(wx)
        point.extend(trace_polynomials.iter().map(|tp| tp.scale(&self.trace_omicron)));

        // 本来はここではない
        // 周期多項式
        let m_h_base = vec![0, 0, 0, 0, 0, 0, 0, 1];
        let m_h_length = self.omicron_domain.len() / 8;
        let m_h: Vec<FieldElement> = m_h_base
        .iter()
        .cycle()
        .take(m_h_length)
        .map(|&b| FieldElement::new(b as u128, self.field))
        .collect();
        let m_h_poly = Polynomial::interpolate_domain_fft(&self.omicron_domain, &m_h);
        // m_p
        let m_p_base = vec![1, 1, 1, 1, 1, 1, 1, 1];
        let m_p_length = self.omicron_domain.len() / 8;
        let m_p: Vec<FieldElement> = (0..m_p_length)
        .flat_map(|block_index| {
        let weight = 1 << block_index; // 2^block_index
        m_p_base.iter().map(move |_| FieldElement::new(weight, self.field))
        })
        .collect();
        let m_p_poly = Polynomial::interpolate_domain_fft(&self.omicron_domain, &m_p);
        // m_s
        let mut m_s_base =  vec![Field::zero(self.field); 1024];
        m_s_base[1023] = Field::one(self.field);
        let m_s_length = self.omicron_domain.len() / 1024;
        let m_s: Vec<FieldElement> = m_s_base
            .iter()
            .cycle()
            .take(m_s_length)
            .map(|&b| FieldElement::new(b.value, self.field))
            .collect();
        let m_s_poly = Polynomial::interpolate_domain_fft(&self.omicron_domain, &m_s);

        point.extend([m_h_poly.clone(), m_p_poly.clone(), m_s_poly.clone()]);

        println!("Generating transition quotient polynomials...");
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
        let bqdbs_prove = self.boundary_quotient_degree_bounds(trace.len(), boundary);
        for (s, bq) in boundary_quotients.iter().enumerate() {
            let shift = if let Some(&idx) = register_to_index.get(&s) {
                max_deg - bqdbs_prove[idx]
            } else {
                0  // 制約なしレジスタはゼロ多項式なので shift 値は結果に影響しない
            };
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

        // prove と対称な register_to_index マップを構築し、制約のないレジスタの OOB アクセスを防ぐ
        let mut constrained_list_v: Vec<usize> = boundary.iter().map(|&(_, r, _)| r).collect();
        constrained_list_v.sort_unstable();
        constrained_list_v.dedup();
        let register_to_index: HashMap<usize, usize> = constrained_list_v
            .iter()
            .enumerate()
            .map(|(idx, reg)| (*reg, idx))
            .collect();
        let boundary_zerofiers = self.boundary_zerofiers(boundary);
        let boundary_interpolants = self.boundary_interpolants(boundary);
        let bqdbs_verify = self.boundary_quotient_degree_bounds(randomized_trace_length, boundary);
        let max_deg_v = self.max_degree(transition_constraints);

        // 各インデックスで「線形結合値」と「FRI値」を照合
        for (i_idx, &i) in indices.iter().enumerate() {
            let domain_current_index = &self.generator * &self.omega.pow(i);
            let next_index = (i + self.expansion_factor as u128) % self.fri.domain_length;
            let domain_next_index = &self.generator * &self.omega.pow(next_index);

            let mut current_trace = vec![self.field.zero(); self.num_registers];
            let mut next_trace = vec![self.field.zero(); self.num_registers];

            for s in 0..self.num_registers {
                if let Some(&idx) = register_to_index.get(&s) {
                    let zerofier = &boundary_zerofiers[idx];
                    let interpolant = &boundary_interpolants[idx];
                    // トレースの復元
                    current_trace[s] = &(&leafs[s][&i] * &zerofier.evaluate(&domain_current_index)) + &interpolant.evaluate(&domain_current_index);
                    next_trace[s] = &(&leafs[s][&next_index] * &zerofier.evaluate(&domain_next_index)) + &interpolant.evaluate(&domain_next_index);
                }
                // 制約なしレジスタは leafs の値が 0 (ゼロ多項式) なので current/next_trace はゼロのまま
            }

            // 遷移制約の評価
            let mut point = vec![domain_current_index];
            point.extend(current_trace.clone());
            point.extend(next_trace);

            let transition_values: Vec<FieldElement> = transition_constraints.iter().map(|tc| tc.evaluate(&point)).collect();

            let mut terms = vec![randomizer[&i]];
            for (s, tcv) in transition_values.iter().enumerate() {
                let quotient = tcv / &self.transition_zerofier().evaluate(&domain_current_index);
                let shift = max_deg_v - self.transition_quotient_degree_bounds(transition_constraints)[s];
                terms.push(quotient);
                terms.push(&quotient * &domain_current_index.pow(shift as u128));
            }
            for s in 0..self.num_registers {
                let bqv = leafs[s][&i];
                let shift = if let Some(&idx) = register_to_index.get(&s) {
                    max_deg_v - bqdbs_verify[idx]
                } else {
                    0  // 制約なしレジスタは bqv=0 なので shift 値は結果に影響しない
                };
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
        
        let boundary = vec![(0, 0, FieldElement::new(1, field)), (1023, 1, FieldElement::new(2, field))];
        let zerofiers = stark.boundary_zerofiers(&boundary);
        assert_eq!(zerofiers.len(), boundary.len());
    }
    // BUG-3: verify の boundary_zerofiers[s] が境界外アクセスしてパニックするバグの再現テスト。
    // 2 レジスタのうちレジスタ 0 のみに境界制約を持つ STARK で prove → verify を実行する。
    // レジスタ 1 は制約なしのため boundary_zerofiers.len()==1 だが verify ループで s=1 でアクセスしパニック。
    // catch_unwind でパニックを検出し、パニックしないことを assert するので:
    //   - バグあり: verify がパニック → catch_unwind が Err → assert 失敗 → テスト FAILED
    //   - バグ修正後: verify がパニックしない → catch_unwind が Ok → assert 成功 → テスト PASSED
    #[test]
    fn test_bug3_verify_does_not_panic_with_unconstrained_registers() {
        use std::panic;

        let field = Field::new(340282366920938463463374557953744961537);
        // 2 registers: register 0 は境界制約あり、register 1 は境界制約なし
        // num_cycles=4, expansion_factor=256: fri_domain_length=1024 (FRI 2 ラウンド成立)
        // 境界制約を trace_degree=3 点ぶん設定 → zerofier 次数3 = trace_degree → quotient 次数 0
        // 遷移制約なし → max_degree=0, shift=0-0=0 でオーバーフローしない
        let stark = Stark::new(
            field,
            256, // expansion_factor (fri_domain_length=4*256=1024 で FRI が成立)
            1,   // num_colinearity_checks
            2,   // security_level
            2,   // num_registers
            4,   // num_cycles
            1,   // transition_constraints_degree
        );

        // register 0 に trace_degree(=3) 点の境界制約 → boundary quotient 次数 = 0
        // register 1 は一切制約なし
        let boundary = vec![
            (0usize, 0usize, FieldElement::new(1, field)),
            (1usize, 0usize, FieldElement::new(1, field)),
            (2usize, 0usize, FieldElement::new(1, field)),
        ];

        // 境界を満たす単純なトレース (register0=1, register1=2 で固定)
        let mut trace: Vec<Vec<FieldElement>> = (0..4)
            .map(|_| vec![FieldElement::new(1, field), FieldElement::new(2, field)])
            .collect();

        let transition_constraints: Vec<MPolynomial> = vec![];
        let mut proof_stream = ProofStream::new();
        let proof_bytes = stark.prove(&mut trace, &transition_constraints, &boundary, &mut proof_stream);

        // verify は register 1 が unconstrained なのに boundary_zerofiers[1] にアクセスしてパニックする
        let mut verifier_stream = ProofStream::deserialize(&proof_bytes);
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            stark.verify(&transition_constraints, &boundary, &mut verifier_stream)
        }));
        assert!(result.is_ok(), "verify はパニックしてはいけない。境界外アクセスのバグが残っている可能性あり");
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

    // TEST-3: STARK prove → verify の end-to-end テスト
    // 1 レジスタ、4 ステップの定数トレース (register 0 = 1) に対して
    // prove が生成した証明を verify で検証し true が返ることを確認する。
    //
    // 注意: 遷移制約を追加すると `max_deg - transition_quotient_degree_bounds` が
    // usize のアンダーフローを起こす既知の問題があるため、ここでは境界制約のみを使用する。
    // 遷移制約の e2e テストは transition_quotient_degree_bounds の修正後に追加する。
    #[test]
    fn test_stark_prove_verify_e2e() {
        let field = Field::new(340282366920938463463374557953744961537);
        let stark = Stark::new(
            field,
            256, // expansion_factor
            1,   // num_colinearity_checks
            2,   // security_level
            1,   // num_registers
            4,   // num_cycles
            1,   // transition_constraints_degree
        );

        // 全ステップで register 0 = 1 の定数トレース
        let mut trace: Vec<Vec<FieldElement>> = (0..4)
            .map(|_| vec![FieldElement::new(1, field)])
            .collect();

        // 境界制約: ステップ 0, 1, 3 で register 0 = 1
        // max_step = 3 → verify 内の original_trace_length = 4 = trace.len() と一致
        // zerofier 次数 = 3 = trace 次数 → boundary quotient 次数 = 0 → shift = 0
        let boundary = vec![
            (0usize, 0usize, FieldElement::new(1, field)),
            (1usize, 0usize, FieldElement::new(1, field)),
            (3usize, 0usize, FieldElement::new(1, field)),
        ];

        let transition_constraints: Vec<MPolynomial> = vec![];
        let mut proof_stream = ProofStream::new();
        let proof_bytes = stark.prove(&mut trace, &transition_constraints, &boundary, &mut proof_stream);

        let mut verifier_stream = ProofStream::deserialize(&proof_bytes);
        let is_valid = stark.verify(&transition_constraints, &boundary, &mut verifier_stream);
        assert!(is_valid, "STARK e2e: verify が true を返すべき");
    }
}
