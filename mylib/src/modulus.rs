use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldElement {
    pub value: u128,
    pub field: Field,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub p: u128, // 素数（有限体のオーダー）
}

impl Field {
    pub fn new(p: u128) -> Field {
        assert!(p > 1, "Field prime must be greater than 1");
        Field { p }
    }
    pub fn zero(self) -> FieldElement {
        FieldElement{value: 0, field: self}
    }

    pub fn one(self) -> FieldElement {
        FieldElement{value: 1, field: self}
    }
    // 暫定
    pub fn generator(self) -> FieldElement {
        FieldElement{value: 3, field: self}
    }
    
    pub fn primitive_nth_root(self, n: u128) -> FieldElement {
        assert!(n > 0 && (self.p - 1) % n == 0, "n must divide p - 1");
        self.generator().pow((self.p - 1) / n)
    }

    // ランダム生成
    pub fn sample(self, byte_array: Vec<u8>) -> FieldElement {
        let mut acc = BigUint::zero();
    
        for b in byte_array {
            acc = (acc << 8) + BigUint::from(b);
        }
    
        let p_big = BigUint::from(self.p);
        let reduced = acc % p_big;
    
        FieldElement {
            value: reduced.to_u128().expect("Field element too large for u128"),
            field: self,
        }
    }
    
}

impl FieldElement {
    pub fn new(value: u128, field: Field) -> FieldElement {
        FieldElement {value: value % field.p, field: field}
    }
    pub fn from_bits(bits: &[char], field: Field) -> FieldElement {
        let two = FieldElement::new(2, field);
        let mut acc = Field::zero(field);

        for (i, &bit) in bits.iter().rev().enumerate() {
            if bit == '1' {
                acc = &acc + &two.pow(i as u128);
            }
        }
        acc
    }
    // フィールド要素の加算
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        // オーバーフローを検出し、剰余計算
        let (sum, overflow) = self.value.overflowing_add(other.value);
        let result = if overflow || sum >= self.field.p {
            // 2^128+sum-p ≡ sum-p mod 2^128
            sum.wrapping_sub(self.field.p)
        } else {
            sum
        };
        FieldElement {
            value: result,
            field: self.field,
        }
    }

    // フィールド要素の減算
    pub fn subtract(&self, other: &FieldElement) -> FieldElement {
        let p = self.field.p;
    
        let result = if self.value >= other.value {
            self.value - other.value
        } else {
            p - (other.value - self.value)
        };
    
        FieldElement {
            value: result,
            field: self.field,
        }
    }

    // フィールド要素の掛け算
    pub fn multiply(&self, other: &FieldElement) -> FieldElement {
        // オーバーフロー判定によりBigIntによる演算コストを軽減
        match self.value.checked_mul(other.value) {
            Some(product) => FieldElement {
                value: product % self.field.p,
                field: self.field,
            },
            None => {
                let a = BigUint::from(self.value);
                let b = BigUint::from(other.value);
                let p = BigUint::from(self.field.p);
                let res = (a * b) % &p;
                FieldElement {
                    value: res.to_u128().expect("BigInt result overflow"),
                    field: self.field,
                }
            }
        }
    }

    // フィールド要素の除算
    pub fn divide(&self, other: &FieldElement) -> FieldElement {
        assert!(other.value != 0, "divide by zero");
        self.multiply(&other.inverse())
    }

    // フィールド要素の負数
    pub fn negate(&self) -> FieldElement {
        FieldElement {
            value: if self.value == 0 { 0 } else { self.field.p - self.value },
            field: self.field,
        }
    }

    // フェルマーの小定理で逆元を計算
    pub fn inverse(&self) -> FieldElement {
        assert!(!self.is_zero(), "Attempted inverse of zero");
        self.pow(self.field.p - 2)
    }
    

    // 繰り返し二乗法による累乗計算
    pub fn pow(&self, exponent: u128) -> FieldElement {
        let mut acc = self.field.one();
        let mut base = *self;
        let mut exp = exponent;
    
        while exp > 0 {
            if exp % 2 == 1 {
                acc = &acc * &base;
            }
            base = &base * &base;
            exp /= 2;
        }
        acc
    }
    

    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

}

// 演算子オーバーロード
use std::ops::{Add, Sub, Mul, Div, Neg};

impl<'a, 'b> Add<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;
    fn add(self, rhs: &'b FieldElement) -> FieldElement {
        self.add(rhs)
    }
}

impl<'a, 'b> Sub<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;
    fn sub(self, rhs: &'b FieldElement) -> FieldElement {
        self.subtract(rhs)
    }
}

impl<'a, 'b> Mul<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;
    fn mul(self, rhs: &'b FieldElement) -> FieldElement {
        self.multiply(rhs)
    }
}

impl<'a, 'b> Div<&'b FieldElement> for &'a FieldElement {
    type Output = FieldElement;
    fn div(self, rhs: &'b FieldElement) -> FieldElement {
        self.divide(rhs)
    }
}

impl Neg for &FieldElement {
    type Output = FieldElement;
    fn neg(self) -> FieldElement {
        self.negate()
    }
}

impl std::ops::BitXor<u128> for FieldElement {
    type Output = FieldElement;
    fn bitxor(self, exponent: u128) -> FieldElement {
        self.pow(exponent)
    }
}

// テスト
#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::{Zero, ToPrimitive};

    #[test]
    fn test_from_bits() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field::new(p);
        
        // ビット列からフィールド要素を生成
        let bits = vec!['1', '0', '1', '1']; // 1011 = 11
        let element = FieldElement::from_bits(&bits, field);
        assert_eq!(element.value, 11);
    }
    // ランダムなフィールド要素の生成
    #[test]
    fn test_sample() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};

        // 一貫性のあるフィールド要素を生成
        let bytes = vec![0x01, 0x02]; // 0x0102 = 258
        let element = field.sample(bytes.clone());
        // BigUintで期待値を計算
        let mut acc = BigUint::zero();
        for b in bytes {
            acc = (acc << 8) + BigUint::from(b);
        }
        let expected_value = (acc % BigUint::from(field.p)).to_u128().unwrap();
        assert_eq!(element.value, expected_value);
        assert_eq!(element.field, field);

        // フィールドの法に収まっているか
        let bytes = vec![0xFF; 32]; // 32バイト（256ビット）だが BigUintで処理される
        let element = field.sample(bytes);
        assert!(element.value < field.p);
    }
    // FieldElementの足し算のテスト
    #[test]
    fn test_modulus_add() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        
        // 計算結果が法pを超えない場合のテスト
        let testelement1 = FieldElement::new(1, Field{p});
        let testelement2 = FieldElement::new(2, Field{p});
        assert_eq!(FieldElement::new(3, Field{p}), &testelement1 + &testelement2);
        // 計算結果が法pと同じ値である場合のテスト
        let testelement1 = FieldElement::new(340282366920938463463374557953744961527, Field{p});
        let testelement2 = FieldElement::new(10, Field{p});
        assert_eq!(FieldElement::new(0, Field{p}), &testelement1 + &testelement2);
        // 計算結果が法pを超える場合のテスト
        let testelement1 = FieldElement::new(340282366920938463463374557953744961527, Field{p});
        let testelement2 = FieldElement::new(20, Field{p});
        assert_eq!(FieldElement::new(10, Field{p}), &testelement1 + &testelement2);
        // 計算結果が128ビットを超える場合のテスト
        let testelement1 = FieldElement::new(340282366920938463463374557953744960513, Field{p});
        let testelement2 = FieldElement::new(340282366920938463463374557953744961527, Field{p});
        assert_eq!(FieldElement::new(340282366920938463463374557953744960503, Field{p}), &testelement1 + &testelement2);
    }

    // FieldElementの引き算のテスト
    #[test]
    fn test_modulus_sub() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        
        // 計算結果が負数にならない場合のテスト
        let testelement1 = FieldElement::new(10, Field{p});
        let testelement2 = FieldElement::new(1, Field{p});
        assert_eq!(FieldElement::new(9, Field{p}), &testelement1 - &testelement2);
        // 計算結果が負数になる場合のテスト
        let testelement1 = FieldElement::new(0, Field{p});
        let testelement2 = FieldElement::new(10, Field{p});
        assert_eq!(FieldElement::new(340282366920938463463374557953744961527, Field{p}), &testelement1 - &testelement2);
    }
    // FieldElementの掛け算のテスト
    #[test]
    fn test_modulus_mul() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        
        // 計算結果が法pを超えない場合のテスト
        let testelement1 = FieldElement::new(10, Field{p});
        let testelement2 = FieldElement::new(2, Field{p});
        assert_eq!(FieldElement::new(20, Field{p}), &testelement1 * &testelement2);
        // 計算結果が法pを超える場合のテスト
        let testelement1 = FieldElement::new(170141183460469231731687303715884105720, Field{p});
        let testelement2 = FieldElement::new(2, Field{p});
        assert_eq!(FieldElement::new(49478023249903, Field{p}), &testelement1 * &testelement2);
        // 計算結果が128ビットを超える場合のテスト
        let testelement1 = FieldElement::new(170141183460469231731687303715884105720, Field{p});
        let testelement2 = FieldElement::new(5, Field{p});
        assert_eq!(FieldElement::new(170141183460469231731687402671930605526, Field{p}), &testelement1 * &testelement2);

    }
    // FieldElementの逆元のテスト
    #[test]
    fn test_inverse() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let testelement1 = FieldElement::new(2, Field{p});
        assert_eq!(FieldElement::new(170141183460469231731687278976872480769, Field{p}), testelement1.inverse());
    }
    // FieldElementの割り算のテスト
    #[test]
    fn test_modulus_div() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let testelement1 = FieldElement::new(4, Field{p});
        let testelement2 = FieldElement::new(3, Field{p});
        assert_eq!(FieldElement::new(113427455640312821154458185984581653847, Field{p}), &testelement1 / &testelement2);
    }
    // FieldElementの累乗のテスト
    #[test]
    fn test_modulus_pow() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let testelement1 = FieldElement::new(2, Field{p});
        assert_eq!(FieldElement::new(1267650600228229401496703205376, Field{p}), testelement1.pow(100));
        assert_eq!(FieldElement::new(197912092999676, Field{p}), testelement1.pow(130));
    }
}