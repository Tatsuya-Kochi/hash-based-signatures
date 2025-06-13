use serde::{Serialize, Deserialize};
use bincode;
use blake3;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProofStream {
    objects: Vec<Vec<u8>>, // 各オブジェクトをシリアライズしたバイト列
    read_index: usize,
}

impl ProofStream {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            read_index: 0,
        }
    }

    pub fn push<T: Serialize>(&mut self, obj: &[T]) {
        let serialized = bincode::serialize(obj).expect("Serialization failed");
        self.objects.push(serialized);
    }
    
    pub fn pull<T: for<'de> Deserialize<'de>>(&mut self) -> T {
        if self.read_index >= self.objects.len() {
            panic!("ProofStream: cannot pull object; queue empty.");
        }
        let obj = bincode::deserialize(&self.objects[self.read_index])
            .expect("Deserialization failed");
        self.read_index += 1;
        obj
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self.objects).expect("Serialization failed")
    }

    pub fn deserialize(data: &[u8]) -> Self {
        let objects: Vec<Vec<u8>> = bincode::deserialize(data).expect("Deserialization failed");
        Self {
            objects,
            read_index: 0,
        }
    }

    pub fn prover_fiat_shamir(&self, num_bytes: usize) -> Vec<u8> {
        let serialized_data = self.serialize();
        derive_blake3_key(&serialized_data, num_bytes)
    }

    pub fn verifier_fiat_shamir(&self, num_bytes: usize) -> Vec<u8> {
        let serialized = bincode::serialize(&self.objects[..self.read_index])
            .expect("Serialization failed");
        derive_blake3_key(&serialized, num_bytes)
    }
}

// 擬似的な可変長出力を BLAKE3 で実現
fn derive_blake3_key(input: &[u8], num_bytes: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(num_bytes);
    let mut counter = 0u32;
    while output.len() < num_bytes {
        let mut context = input.to_vec();
        context.extend_from_slice(&counter.to_le_bytes());
        let hash = blake3::hash(&context);
        output.extend_from_slice(hash.as_bytes());
        counter += 1;
    }
    output.truncate(num_bytes);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Dummy {
        a: u32,
        b: Vec<u8>,
    }

    #[test]
    fn test_push_and_pull() {
        let mut ps = ProofStream::new();
        let input = vec![Dummy { a: 1, b: vec![10, 20] }, Dummy { a: 2, b: vec![30] }];
        ps.push(&input);

        let output: Vec<Dummy> = ps.pull();
        assert_eq!(input, output);
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut ps = ProofStream::new();
        ps.push(&vec![123u32, 456u32]);

        let serialized = ps.serialize();
        let mut deserialized = ProofStream::deserialize(&serialized);

        let output: Vec<u32> = deserialized.pull();
        assert_eq!(output, vec![123, 456]);
    }

    #[test]
    fn test_fiat_shamir_consistency() {
        let mut ps = ProofStream::new();
        ps.push(&vec![1u32, 2u32, 3u32]);

        let challenge_prover = ps.prover_fiat_shamir(32);

        let _: Vec<u32> = ps.pull(); // 読み出すことで read_index を進める

        let challenge_verifier = ps.verifier_fiat_shamir(32);

        assert_eq!(challenge_prover, challenge_verifier);
    }

    #[test]
    fn test_fiat_shamir_diff() {
        let mut ps1 = ProofStream::new();
        let mut ps2 = ProofStream::new();
        ps1.push(&vec![1u32, 2u32]);
        ps2.push(&vec![2u32, 1u32]); // 順序を変えて違うもの

        let hash1 = ps1.prover_fiat_shamir(32);
        let hash2 = ps2.prover_fiat_shamir(32);

        assert_ne!(hash1, hash2);
    }
}
