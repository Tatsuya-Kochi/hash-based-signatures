use crate::{modulus::FieldElement, rescue_prime};
use crate::modulus::Field;
use rescue_prime::RescuePrime;
use blake3;

pub struct Merkle{
    pub rp: RescuePrime,
}

impl Merkle {
    pub fn new() -> Self {
        let rp = RescuePrime::new();
        Merkle{
            rp,
        }
    }

    // 閾値署名では、ダミーの葉を追加することがある
    pub fn rescue_commit(&self, leafs: &[Vec<FieldElement>]) -> Vec<FieldElement> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        if leafs.len() == 1 {
            return leafs[0].clone();
        } else {
            let mid = leafs.len() / 2;
            let left_commit = self.rescue_commit(&leafs[..mid]);
            let right_commit = self.rescue_commit(&leafs[mid..]);

            assert_eq!(left_commit.len(), 2);
            assert_eq!(right_commit.len(), 2);
            let input: [FieldElement; 4] = [
                left_commit[0], left_commit[1],
                right_commit[0], right_commit[1],
            ];
            self.rp.hash(input).to_vec()
        }
    }

    pub fn blake_commit(&self, leafs: &[Vec<u8>]) -> Vec<u8> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        if leafs.len() == 1 {
            return leafs[0].clone();
        } else {
            let mid = leafs.len() / 2;
            let left_commit = self.blake_commit(&leafs[..mid]);
            let right_commit = self.blake_commit(&leafs[mid..]);
            let root = blake3::hash(&[left_commit, right_commit].concat());
            root.as_bytes().to_vec()
        }
    }


    pub fn rescue_open(&self, index: usize, leafs: &[Vec<FieldElement>]) -> Vec<Vec<FieldElement>> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        assert!(index < leafs.len(), "cannot open invalid index");

        if leafs.len() == 2 {
            return vec![leafs[1 - index].clone()];
        } else {
            let mid = leafs.len() / 2;
            if index < mid {
                let mut path = self.rescue_open(index, &leafs[..mid]);
                path.push(self.rescue_commit(&leafs[mid..]));
                path
            } else {
                let mut path = self.rescue_open(index - mid, &leafs[mid..]);
                path.push(self.rescue_commit(&leafs[..mid]));
                path
            }
        }
    }

    fn rescue_open_inner_threshold(&self, index: usize, leafs: &[Vec<FieldElement>], path: &mut Vec<Vec<FieldElement>>) {
        if leafs.len() == 2 {
            // sibling を push
            path.push(leafs[1 - index].clone());
        } else {
            let mid = leafs.len() / 2;
            if index < mid {
                self.rescue_open_inner_threshold(index, &leafs[..mid], path);
                path.push(self.rescue_commit(&leafs[mid..])); // right sibling
            } else {
                self.rescue_open_inner_threshold(index - mid, &leafs[mid..], path);
                path.push(self.rescue_commit(&leafs[..mid])); // left sibling
            }
        }
    }

    // 閾値署名のMerkle証明では、path[0]にインデックスの葉の値を入れる
    pub fn rescue_open_thereshold(&self, index: usize, leafs: &[Vec<FieldElement>]) -> Vec<Vec<FieldElement>> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        assert!(index < leafs.len(), "cannot open invalid index");
    
        // path[0] に leaf[index] を追加
        let mut path = vec![leafs[index].clone()];
    
        // path[1..] に sibling nodes を push
        self.rescue_open_inner_threshold(index, leafs, &mut path);
    
        path
    }

    pub fn blake_open(&self, index: usize, leafs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        assert!(index < leafs.len(), "cannot open invalid index");

        if leafs.len() == 2 {
            return vec![leafs[1 - index].clone()];
        } else {
            let mid = leafs.len() / 2;
            if index < mid {
                let mut path = self.blake_open(index, &leafs[..mid]);
                path.push(self.blake_commit(&leafs[mid..]));
                path
            } else {
                let mut path = self.blake_open(index - mid, &leafs[mid..]);
                path.push(self.blake_commit(&leafs[..mid]));
                path
            }
        }
    }

    pub fn rescue_verify(&mut self, root: &[FieldElement; 2], index: usize, path: &[Vec<FieldElement>], leaf: Vec<FieldElement>) -> bool {
        assert!(index < (1 << path.len()), "cannot verify invalid index");

        assert_eq!(leaf.len(), 2);
        assert_eq!(path[0].len(), 2);

        if path.len() == 1 {
            let input: [FieldElement; 4] = if index == 0 {
                [leaf[0], leaf[1], path[0][0], path[0][1]]
            } else {
                [path[0][0], path[0][1], leaf[0], leaf[1]]
            };
            return root == &self.rp.hash(input);
        } else {
            let next_leaf = if index % 2 == 0 {
                [leaf[0], leaf[1], path[0][0], path[0][1]]
            } else {
                [path[0][0], path[0][1], leaf[0], leaf[1]]
            };
            self.rescue_verify(root, index >> 1, &path[1..], self.rp.hash(next_leaf).to_vec())
        }
    }

    // 閾値署名の検証
    pub fn rescue_verify_threshold(&mut self, root: &Vec<FieldElement>, index: usize, path: &[Vec<FieldElement>]) 
    -> (bool, Vec<[FieldElement; 8]>) {
        assert!(index < (1 << path.len()), "cannot verify invalid index");
        assert!(!path.is_empty());
        assert_eq!(path[0].len(), 2);
        let little_endian = to_little_endian_bit_vec(index, index+1);
        let mut total_index: u128  = 0;

        let mut traces = vec![[Field::zero(self.rp.field); 8]; path.len()*8];
        let mut r = [Field::zero(self.rp.field), Field::zero(self.rp.field)]; // 初期化

        // Step 1: 初期化 r = hash(path[0], 0)
        let zero = FieldElement::new(0, self.rp.field); // 適切な Field を使う
        let input: [FieldElement; 4] = [path[0][0], path[0][1], zero, zero];
        let mut rescue_trace = [[Field::zero(self.rp.field); 6]; 8]; // 初期化
        (rescue_trace, r) = self.rp.hash_with_trace(input);
        for j in 0..8 {
            traces[j][0] = Field::zero(self.rp.field);
            traces[j][1] = FieldElement::new(little_endian[0] as u128, self.rp.field);
            traces[j][2..8].copy_from_slice(&rescue_trace[j]);
        }
        total_index += little_endian[0] as u128;

        // Step 2: path[1..] に沿って hash を更新
        for (i, sibling) in path.iter().enumerate().skip(1) {
            assert_eq!(sibling.len(), 2);
            let mut rescue_trace = [[Field::zero(self.rp.field); 6]; 8];

            let input: [FieldElement; 4] = if ((index >> (i - 1)) & 1) == 0 {
                [r[0], r[1], sibling[0], sibling[1]]
            } else {
                [sibling[0], sibling[1], r[0], r[1]]
            };

            let (trace_tmp, r_tmp) = self.rp.hash_with_trace(input);
            rescue_trace = trace_tmp;
            r = r_tmp;

            for j in 0..8 {
                traces[(i*8)+j][0] = FieldElement::new(total_index as u128, self.rp.field);
                traces[(i*8)+j][1] = FieldElement::new(little_endian[i] as u128, self.rp.field);
                traces[(i*8)+j][2..8].copy_from_slice(&rescue_trace[j]);
            }
            total_index += little_endian[i] as u128 * (1u128 << i);
        }
        // Step 3: root と比較
        (r[0] == root[0] && r[1] == root[1], traces)
    }

    pub fn blake_verify(&self, root: Vec<u8>, index: usize, path: &[Vec<u8>], leaf: Vec<u8>) -> bool {
        assert!(index < (1 << path.len()), "cannot verify invalid index: index={}, path.len()={}", index, path.len());
    
        if path.is_empty() {
            return root == leaf;
        }
    
        let parent_hash = if index % 2 == 0 {
            blake3::hash(&[&leaf[..], &path[0][..]].concat()).as_bytes().to_vec()
        } else {
            blake3::hash(&[&path[0][..], &leaf[..]].concat()).as_bytes().to_vec()
        };
    
        self.blake_verify(root, index >> 1, &path[1..], parent_hash)
    }
}

pub fn prepare_data(array_data: &Vec<FieldElement>) -> Vec<Vec<u8>> {
    array_data.iter().map(|fe| fe.value.to_be_bytes().to_vec()).collect()
}

pub fn to_little_endian_bit_vec(n: usize, bit_length: usize) -> Vec<u8> {
    (0..bit_length)
        .map(|i| ((n >> i) & 1) as u8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modulus::{Field, FieldElement};

    #[test]
    fn test_rescue_merkle_commit_open_verify() {
        let p: u128 = 340282366920938463463374557953744961537;
        let field = Field::new(p);

        // 4葉のMerkleツリー（[FieldElement; 2]型の葉）
        let leaves_data = vec![
            vec![FieldElement::new(2, field.clone()), FieldElement::new(70, field.clone())],
            vec![FieldElement::new(10, field.clone()), FieldElement::new(99, field.clone())],
            vec![FieldElement::new(42, field.clone()), FieldElement::new(66, field.clone())],
            vec![FieldElement::new(14, field.clone()), FieldElement::new(19, field.clone())],
        ];

        let mut merkle = Merkle::new();
        let root = merkle.rescue_commit(&leaves_data);
        assert_eq!(root.len(), 2);

        for (i, leaf) in leaves_data.iter().enumerate() {
            let path = merkle.rescue_open(i, &leaves_data);
            let root_arr: [FieldElement; 2] = root.clone().try_into().expect("expected root len 2");
            let is_valid = merkle.rescue_verify(&root_arr, i, &path, leaf.clone());
            assert!(is_valid, "proof should verify for index {}", i);
        }
    }
    // BUG-2: total_index の累積計算で `2^i` が XOR になっていたバグの再現テスト。
    // index=6 (2進数 110)、path.len()=4(葉含む) の 8 葉ツリーを使う。
    // little_endian[0..4] = [0, 1, 1, 0]
    //
    // ループ i=1 の更新後 (traces[16][0] に記録される値):
    //   正しくは: 0 + 1 * 2^1 = 2
    //   XOR バグ: 0 + 1 * 2 * (2 XOR 1) = 1 * 2 * 3 = 6
    #[test]
    fn test_bug2_total_index_accumulation() {
        let p: u128 = 340282366920938463463374557953744961537;
        let field = Field::new(p);
        let mut merkle = Merkle::new();

        let leaves_data: Vec<Vec<FieldElement>> = (0u128..8)
            .map(|v| vec![FieldElement::new(v, field), FieldElement::new(v * 10, field)])
            .collect();

        let root = merkle.rescue_commit(&leaves_data);
        let index = 6usize; // 2進数 110 → little_endian = [0, 1, 1, ...]
        let path = merkle.rescue_open_thereshold(index, &leaves_data);
        // path.len() == 4 (path[0]=leaf, path[1..4]=siblings)

        let (_is_valid, traces) = merkle.rescue_verify_threshold(&root, index, &path);

        // ループ i=2 の開始時点で記録される total_index (traces[16][0]) を確認する。
        // これはループ i=1 の更新後の値: little_endian[0] + little_endian[1] * 2^1
        //   = 0 + 1 * 2 = 2 (correct)
        //   XOR bug では 0 + 1*2*(2 XOR 1) = 6
        let total_index_at_i2 = traces[16][0].value;
        assert_eq!(
            total_index_at_i2, 2,
            "total_index after i=1 step should be 2 (= 0 + 1*2^1), got {}",
            total_index_at_i2
        );
    }

    #[test]
    fn test_blake_merkle_commit_open_verify() {
        let p: u128 = 340282366920938463463374557953744961537;
        let field = Field::new(p);

        // 4葉のMerkleツリー（1葉あたり FieldElement 1個とする）
        let leaves_fe = vec![
            FieldElement::new(2, field.clone()),
            FieldElement::new(10, field.clone()),
            FieldElement::new(42, field.clone()),
            FieldElement::new(14, field.clone()),
        ];

        // FieldElement → Vec<u8>（BigEndian）変換
        let leaves_bytes: Vec<Vec<u8>> = leaves_fe
            .iter()
            .map(|fe| fe.value.to_be_bytes().to_vec())
            .collect();

        let mut merkle = Merkle::new();
        let root = merkle.blake_commit(&leaves_bytes);

        for (i, leaf_fe) in leaves_fe.iter().enumerate() {
            let path = merkle.blake_open(i, &leaves_bytes);
            let leaf_bytes = leaf_fe.value.to_be_bytes().to_vec();
            let is_valid = merkle.blake_verify(root.clone(), i, &path, leaf_bytes);
            assert!(is_valid, "BLAKE3 Merkle proof should verify at index {}", i);
        }
    }
}
