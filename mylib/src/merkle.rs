use crate::{modulus::FieldElement, rescue_prime};
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

    // Merkle木のルートを計算する（コミットフェーズ）
    pub fn commit(&self, leafs: Vec<Vec<FieldElement>>) -> Vec<FieldElement> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        if leafs.len() == 1 {
            return leafs[0].clone();
        } else {
            let mid = leafs.len() / 2;
            let left_commit = self.commit(leafs[..mid].to_vec());
            let right_commit = self.commit(leafs[mid..].to_vec());
            self.rp.hash([left_commit, right_commit].concat())
        }
    }

    // Merkle木のルートを計算する（コミットフェーズ）
    pub fn blake_commit(&self, leafs: Vec<Vec<u8>>) -> Vec<u8> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");

        // 葉が1つだけの場合、その葉を返す
        if leafs.len() == 1 {
            return leafs[0].clone();
        } else {
            // 葉の配列を分割して左と右のコミットメントを再帰的に計算
            let mid = leafs.len() / 2;
            let left_commit = self.blake_commit(leafs[..mid].to_vec());
            let right_commit = self.blake_commit(leafs[mid..].to_vec());

            // 左右のコミットメントを連結し、その結果をBlake3でハッシュ
            let root = blake3::hash(&[left_commit, right_commit].concat());
            
            // ハッシュ結果を Vec<u8> として返す
            root.as_bytes().to_vec()
        }
}


    // Merkle木の証明を開く
    pub fn open(&self, index: usize, leafs: Vec<Vec<FieldElement>>) -> Vec<Vec<FieldElement>> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        assert!(index < leafs.len(), "cannot open invalid index");
        
        if leafs.len() == 2 {
            return vec![leafs[1 - index].clone()];
        } else {
            let mid = leafs.len() / 2;
            if index < mid {
                let mut path = self.open(index, leafs[..mid].to_vec());
                path.push(self.commit(leafs[mid..].to_vec()));
                path
            } else {
                let mut path = self.open(index - mid, leafs[mid..].to_vec());
                path.push(self.commit(leafs[..mid].to_vec()));
                path
            }
        }
    }

    // Merkle木の証明を開く
    pub fn blake_open(&self, index: usize, leafs: Vec<FieldElement>) -> Vec<Vec<u8>> {
        assert!(leafs.len().is_power_of_two(), "length must be power of two");
        assert!(index < leafs.len(), "cannot open invalid index");
    
        let leafs_bytes = prepare_data(leafs.clone()); // バイト配列に変換
        
        if leafs_bytes.len() == 2 {
            // 葉の数が2つだけの場合、もう一方の葉を返す
            return vec![leafs_bytes[1 - index].clone()];
        } else {
            let mid = leafs.len() / 2;
    
            if index < mid {
                // 左側のブランチを辿る場合
                let mut path = self.blake_open(index, leafs[..mid].to_vec());
                path.push(self.blake_commit(leafs_bytes[mid..].to_vec())); // 右のサブツリーのコミットメントを追加
                path
            } else {
                // 右側のブランチを辿る場合
                let mut path = self.blake_open(index - mid, leafs[mid..].to_vec());
                path.push(self.blake_commit(leafs_bytes[..mid].to_vec())); // 左のサブツリーのコミットメントを追加
                path
            }
        }
    }
    

    // Merkle木の証明を検証する
    pub fn verify(&mut self, root: Vec<FieldElement>, index: usize, path: Vec<Vec<FieldElement>>, leaf: Vec<FieldElement>) -> bool {
        assert!(index < (1 << path.len()), "cannot verify invalid index");

        if path.len() == 1 {
            if index == 0 {
                return root == self.rp.hash([leaf, path[0].clone()].concat());
            } else {
                return root == self.rp.hash([path[0].clone(), leaf].concat());
            }
        } else {
            if index % 2 == 0 {
                return self.verify(root, index >> 1, path[1..].to_vec(), self.rp.hash([leaf, path[0].clone()].concat()));
            } else {
                return self.verify(root, index >> 1, path[1..].to_vec(), self.rp.hash([path[0].clone(), leaf].concat()));
            }
        }
    }

    pub fn blake_verify(&mut self, root: Vec<u8>, index: u128, path: Vec<Vec<u8>>, leaf: Vec<u8>) -> bool {
        assert!(index < (1 << path.len()), "cannot verify invalid index");

        if path.len() == 1 {
            if index == 0 {
                return root == blake3::hash(&[leaf, path[0].clone()].concat()).as_bytes().to_vec();
            } else {
                return root == blake3::hash(&[path[0].clone(), leaf].concat()).as_bytes().to_vec();
            }
        } else {
            if index % 2 == 0 {
                return self.blake_verify(root, index >> 1, path[1..].to_vec(), blake3::hash(&[leaf, path[0].clone()].concat()).as_bytes().to_vec());
            } else {
                return self.blake_verify(root, index >> 1, path[1..].to_vec(), blake3::hash(&[path[0].clone(), leaf].concat()).as_bytes().to_vec());
            }
        }
    }
}

// BLAKEハッシュのためにデータをバイト形式に変換する
pub fn prepare_data(array_data: Vec<FieldElement>) -> Vec<Vec<u8>> {
    let mut byte_array = vec![];
    for i in 0..array_data.len() {
        let bytes = array_data[i].value.to_string().into_bytes(); // バイト列をVec<u8>に変換
        byte_array.push(bytes); // Vec<Vec<u8>>に保持
    }
    byte_array
}
