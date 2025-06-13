use num_bigint::BigInt;
use num_traits::ToPrimitive;
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FieldElement {
    pub value: u128,
    pub field: Field,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub p: u128, // 素数（有限体のオーダー）
}

impl Field {
    pub fn zero(self) -> FieldElement {
        FieldElement{value: 0, field: self}
    }

    pub fn one(self) -> FieldElement {
        FieldElement{value: 1, field: self}
    }
    
    pub fn generator(self) -> FieldElement {
        FieldElement{value: 0, field: self}
    }
    // 要改善
    pub fn primitive_nth_root(self, n: u128) -> FieldElement {
        let mut root = FieldElement{value: 0, field: self};
        let mut order = (1 << 127);
        while order != n {
                root = root^2;
                order = order/2;
        }
        root
    }

    pub fn sample(self, byte_array: Vec<u8>) -> FieldElement {
        let mut acc: u128 = 0; // acc の型を u128 に変更
        for b in byte_array {
            acc = (acc << 8) ^ b as u128; // b を u128 にキャスト
        }
        FieldElement {
            value: (acc % self.p) as u128, // p の型に合わせてキャスト
            field: self,
        }
    }
    
}

impl FieldElement {
    pub fn new(value: u128, field: Field) -> FieldElement {
        // 値が法を超えていたら
        assert!(value < 340282366920938463463374557953744961537, "Value exceeds the modulus");
        FieldElement {value: value, field: field}
    }
    // フィールド要素の加算
    pub fn add(self, other: FieldElement) -> FieldElement {
        let big_int = (BigInt::from(self.value) + BigInt::from(other.value)) % BigInt::from(self.field.p);

        // BigIntがu128の範囲内か確認
        if let Some(u128_value) = big_int.to_u128() {
            FieldElement {
                value: u128_value,
                field: self.field,
            }
        } else {
            FieldElement {
                value: 0,
                field: self.field,
            }
        }
    }

    // フィールド要素の減算
    pub fn subtract(self, other: FieldElement) -> FieldElement {
        let big_int = (BigInt::from(self.value) + BigInt::from(self.field.p) - BigInt::from(other.value)) % BigInt::from(self.field.p);

        // BigIntがu128の範囲内か確認
        if let Some(u128_value) = big_int.to_u128() {
            FieldElement {
                value: u128_value,
                field: self.field,
            }
        } else {
            FieldElement {
                value: 0,
                field: self.field,
            }
        }
    }

    // フィールド要素の掛け算
    pub fn multiply(self, other: FieldElement) -> FieldElement {
        let big_int = BigInt::from(self.value) * BigInt::from(other.value) % BigInt::from(self.field.p);

        // BigIntがu128の範囲内か確認
        if let Some(u128_value) = big_int.to_u128() {
            FieldElement {
                value: u128_value,
                field: self.field,
            }
        } else {
            FieldElement {
                value: 0,
                field: self.field,
            }
        }
    }

    // フィールド要素の除算
    pub fn divide(&self, other: FieldElement) -> FieldElement {
        assert!(other.value != 0, "divide by zero");
        let inv = other.inverse();
        println!("inv={:?}", inv);
        self.multiply(inv)
    }

    // フィールド要素の負数
    pub fn negate(&self) -> FieldElement {
        FieldElement {
            value: (self.field.p - self.value) % self.field.p,
            field: self.field,
        }
    }

    // 拡張ユークリッドの互除法で逆元を計算
    pub fn inverse(&self) -> FieldElement {
        let (a, _b, _g) = xgcd(self.value as i64, self.field.p as i64);
        FieldElement {
            value: a,
            field: self.field,
        }
    }

    // 繰り返し二乗法による累乗計算
    pub fn pow(&self, exponent: u128) -> FieldElement {
        let mut acc = FieldElement {
            value: 1,
            field: self.field,
        };
        let mut base = *self;
        let mut exp = exponent;

        while exp > 0 {
            if exp % 2 != 0 {
                acc = acc.multiply(base);
            }
            base = base.multiply(base);
            exp /= 2;
        }
        acc
    }

    pub fn is_zero(&self) -> bool {
        self.value == 0
    }
}

// 拡張ユークリッドの互除法
pub fn xgcd(a: i64, b: i64) -> (u128, u128, u128) {
    let (mut old_r, mut r) = (BigInt::from(a), BigInt::from(b));
    let (mut old_s, mut s) = (BigInt::from(1), BigInt::from(0));
    let (mut old_t, mut t) = (BigInt::from(0), BigInt::from(1));

    while r != BigInt::from(0) {
        let quotient = &old_r / &r;
        old_r = &old_r - &quotient * &r;
        std::mem::swap(&mut old_r, &mut r);
        old_s = &old_s - &quotient * &s;
        std::mem::swap(&mut old_s, &mut s);
        old_t = &old_t - &quotient * &t;
        std::mem::swap(&mut old_t, &mut t);
    }
    if old_s < BigInt::from(0) {
        old_s = old_s + b
    }
    let s_u128 = old_s.to_u128().expect("Failed to convert old_s to u128");
    let t_u128 = old_t.to_u128().expect("Failed to convert old_t to u128");
    let r_u128 = old_r.to_u128().expect("Failed to convert old_r to u128");

    (s_u128, t_u128, r_u128)
}

// 演算子のオーバーロード
impl std::ops::Add for FieldElement {
    type Output = FieldElement;
    fn add(self, rhs: FieldElement) -> FieldElement {
        self.add(rhs)
    }
}

impl std::ops::Sub for FieldElement {
    type Output = FieldElement;
    fn sub(self, rhs: FieldElement) -> FieldElement {
        self.subtract(rhs)
    }
}

impl std::ops::Mul for FieldElement {
    type Output = FieldElement;
    fn mul(self, rhs: FieldElement) -> FieldElement {
        self.multiply(rhs)
    }
}

impl std::ops::Div for FieldElement {
    type Output = FieldElement;
    fn div(self, rhs: FieldElement) -> FieldElement {
        self.divide(rhs)
    }
}

impl std::ops::Neg for FieldElement {
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
use crate::modulus;
use modulus::modulus::Field as Field;
use modulus::modulus::FieldElement as FieldElement;
// FieldElementの足し算のテスト
#[test]
fn test_add() {
    // 結果がmod計算の法pと128ビットを超える場合のテスト

    let p = 340282366920938463463374557953744961537;
    // testelement1 = p - 2^10
    let testelement1 = FieldElement::new(340282366920938463463374557953744960513, Field{p});
    // testelement2 = p - 10
    let testelement2 = FieldElement::new(340282366920938463463374557953744961527, Field{p});
    // correct_answer = Mod(testelement1+testelement2, p) computed PARI
    let correct_answer = FieldElement::new(340282366920938463463374557953744960503, Field{p});

    let added = testelement1 + testelement2;
    assert_eq!(added.value, correct_answer.value);
}

// FieldElementの引き算のテスト
#[test]
fn test_subtract() {
    // 結果がmod計算の法pと128ビットを超える場合のテスト
    
    let p = 340282366920938463463374557953744961537;
    let testelement1 = FieldElement::new(1, Field{p});
    // testelement2 = p - 10
    let testelement2 = FieldElement::new(340282366920938463463374557953744961527, Field{p});
    // correct_answer = Mod(testelement1+testelement2, p) computed PARI
    let correct_answer = FieldElement::new(11, Field{p});

    let added = testelement1 - testelement2;
    assert_eq!(added.value, correct_answer.value);
}
#[test]
fn test_multiply() {
    // 結果がmod計算の法pと128ビットを超える場合のテスト

    let p = 340282366920938463463374557953744961537;
    // testelement1 = p - 2^10
    let testelement1 = FieldElement::new(340282366920938463463374557953744960513, Field{p});
    // testelement2 = p - 10
    let testelement2 = FieldElement::new(340282366920938463463374557953744961527, Field{p});
    // correct_answer = Mod(testelement1+testelement2, p) computed PARI
    let correct_answer = FieldElement::new(10240, Field{p});

    let added = testelement1 * testelement2;
    assert_eq!(added.value, correct_answer.value);
}
fn test_divide() {

}
fn test_inverce() {

}
}