use serde::{Serialize, Deserialize};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use bincode;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProofStream {
    objects: Vec<Vec<u8>>, // Each object is stored as serialized bytes
    read_index: usize,
}

impl ProofStream {
    pub fn new() -> Self {
        ProofStream {
            objects: Vec::new(),
            read_index: 0,
        }
    }

    // Push an object into the ProofStream
    // 型に依存しない実装 配列を受け取る　単一の値はの一つの要素を持つ配列を渡す
    pub fn push<T: Serialize>(&mut self, obj: &[T]) {
        let serialized_obj = bincode::serialize(obj).expect("Serialization failed");
        self.objects.push(serialized_obj);
    }

    // Pull an object from the ProofStream
    pub fn pull<T: for<'de> Deserialize<'de>>(&mut self) -> T {
        if self.read_index >= self.objects.len() {
            panic!("ProofStream: cannot pull object; queue empty.");
        }
        let obj = bincode::deserialize(&self.objects[self.read_index])
            .expect("Deserialization failed");
        self.read_index += 1;
        obj
    }

    // Serialize the entire ProofStream
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self.objects).expect("Serialization failed")
    }

    // Deserialize a ProofStream from bytes
    pub fn deserialize(data: &[u8]) -> Self {
        let objects: Vec<Vec<u8>> = bincode::deserialize(data).expect("Deserialization failed");
        ProofStream {
            objects,
            read_index: 0,
        }
    }

    // Prover's Fiat-Shamir transformation
    pub fn prover_fiat_shamir(&self, num_bytes: usize) -> Vec<u8> {
        let serialized_data = self.serialize();
        let mut hasher = Shake256::default();
        hasher.update(&serialized_data);
        let mut output = vec![0u8; num_bytes];
        hasher.finalize_xof().read(&mut output);
        output
    }

    // Verifier's Fiat-Shamir transformation
    pub fn verifier_fiat_shamir(&self, num_bytes: usize) -> Vec<u8> {
        let serialized_data = bincode::serialize(&self.objects[..self.read_index])
            .expect("Serialization failed");
        let mut hasher = Shake256::default();
        hasher.update(&serialized_data);
        let mut output = vec![0u8; num_bytes];
        hasher.finalize_xof().read(&mut output);
        output
    }
}
