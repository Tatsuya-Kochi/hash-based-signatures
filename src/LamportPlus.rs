use crate::modulus;
use crate::rescueprime;

pub struct LamportPlus {
    field: Field,
    rp: RescuePrime,
    // capacity部分の状態保持のための変数
    acc: Vec<u128>,
}

pub impl LamportPlus {
    pub fn new() -> Self {
        LamportPlus {
            field: Field::new(P),
            rp: RescuePrime,
            acc: vec![],
        }
    }

    pub fn reduce_message(self, m: &FieldElement) -> (FieldElement, FieldElement) {
        let counter: u128 = 0; //カウンタC
        

    }

    pub fn keygen(&mut self, m0: &FieldElement, m1: &FieldElement) -> (Vec<Vec<FieldElement>>, Vec<Vec<u8>>) {
        let n = m0.value.count_ones() as usize + m1.value.count_ones() as usize;
        let mut pr = vec![];
        let mut pb = vec![];

        let mut rng = rand::thread_rng();
        for _ in 0..n {
            pr.push(vec![
                FieldElement::new(rng.gen(), &self.field),
                FieldElement::new(rng.gen(), &self.field),
            ]);
            pb.push(self.rp.hash(&pr.last().unwrap()[0].value.to_be_bytes()));
        }

        for i in 0..128 {
            self.acc.push(self.rp.hash(&self.acc.concat()));
            self.acc.push(self.rp.hash(&(self.acc.concat() + &pb[i])));
        }

        (pr, pb)
    }

    pub fn sign(&self, m0: &[u8], m1: &[u8], pr: &[Vec<FieldElement>]) -> Vec<Vec<u8>> {
        let pb: Vec<Vec<u8>> = pr.iter().map(|e| self.rp.hash(&e[0].value.to_be_bytes())).collect();
        let mut sig = vec![];

        for i in 0..128 {
            if m0[i] == 1 {
                sig.push(pr[i][0].value.to_be_bytes().to_vec());
            } else {
                sig.push(self.rp.hash(&pr[i][0].value.to_be_bytes()));
            }
            if m1[i] == 1 {
                sig.push(pr[i + 128][0].value.to_be_bytes().to_vec());
            } else {
                sig.push(self.rp.hash(&pr[i + 128][0].value.to_be_bytes()));
            }
        }
        sig
    }

    pub fn verify(&self, m0: &[u8], m1: &[u8], pb: &[Vec<u8>], sig: &[Vec<u8>]) -> bool {
        let mut acc_verify = vec![];
        let mut m0_acc = 0;
        let mut m1_acc = 0;

        for i in 0..128 {
            m0_acc = m0_acc * 2 + if m0[i] == 1 { 1 } else { 0 };
            m1_acc = m1_acc * 2 + if m1[i] == 1 { 1 } else { 0 };

            if m0[i] == 1 {
                acc_verify.push(self.rp.hash(&sig[i]));
            } else {
                acc_verify.push(self.rp.hash(&sig[i]));
            }
            if m1[i] == 1 {
                acc_verify.push(self.rp.hash(&sig[i + 128]));
            } else {
                acc_verify.push(self.rp.hash(&sig[i + 128]));
            }
        }

        m0 == m0_acc.to_be_bytes() && m1 == m1_acc.to_be_bytes() && self.acc == acc_verify
    }
}