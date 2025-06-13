use::mylib::{modulus::{Field, FieldElement}, polynomial, mpolynomial, merkle, proofstream, rescue_prime, lamport_plus, fri, stark, agg_sig};

/// ダミーの単一トレース（3行 × num_registers列）を生成
fn dummy_trace(field: Field, num_registers: usize, steps: usize) -> Vec<Vec<FieldElement>> {
    (0..steps).map(|i| {
        (0..num_registers).map(|j| {
            field.sample(format!("trace-{i}-{j}").into_bytes())
        }).collect()
    }).collect()
}

/// 複数のトレースを結合
fn flatten_traces(traces: Vec<Vec<Vec<FieldElement>>>) -> Vec<Vec<FieldElement>> {
    traces.into_iter().flatten().collect()
}

fn main() {
    let field = Field { p: 340282366920938463463374557953744961537 }; // 2^128 - 45×2^40 + 1
    let num_registers = 4;
    let trace_len_per_block = 8;

    // 3つのトレースを仮に用意
    let trace1 = dummy_trace(field, num_registers, trace_len_per_block);
    let trace2 = dummy_trace(field, num_registers, trace_len_per_block);
    let trace3 = dummy_trace(field, num_registers, trace_len_per_block);

    // 連結
    let mut unified_trace = flatten_traces(vec![trace1, trace2, trace3]);

    // ダミー境界制約とトランジション制約
    let boundary = vec![
        (0, 0, field.one()), // 最初のステップでレジスタ0が1
        (0, 1, field.zero()), // レジスタ1が0
    ];

    use mpolynomial::MPolynomial;
    use std::collections::HashMap;
    let mut t_constraints = vec![];

    // 単純な制約： f(x+1) - f(x)
    for r in 0..num_registers {
        let mut dict = HashMap::new();
        let mut key = vec![0; 1 + 2 * num_registers]; // x, current, next
        key[1 + r] = 1;   // current[r]
        dict.insert(key.clone(), field.one());

        key[1 + num_registers + r] = 1; // next[r]
        dict.insert(key, field.one());
        t_constraints.push(MPolynomial::new(dict));
    }

    // STARK 初期化
    let stark = stark::Stark::new(
        field,
        8,     // expansion factor
        10,    // number of FRI checks
        80,    // security level
        num_registers,
        unified_trace.len(),
        2      // transition constraint degree
    );

    let mut ps = proofstream::ProofStream::new();
    let proof = stark.prove(&mut unified_trace, &t_constraints, &boundary, &mut ps);
    println!("Proof size: {} bytes", proof.len());
}
