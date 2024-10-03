
pub mod modulus {
    extern crate num_bigint;
    use num_bigint::BigInt;
    extern crate num_traits;
    use num_traits::ToPrimitive;
    #[derive(Debug, Clone, Copy)]
    pub struct FieldElement {
        pub value: u128,
        pub field: Field,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Field {
        pub p: u128, // 素数（有限体のオーダー）
    }

    impl FieldElement {
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
            println!("value={}", self.value);
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

        fn is_zero(&self) -> bool {
            self.value == 0
        }
    }

    // 拡張ユークリッドの互除法
    pub fn xgcd(a: i64, b: i64) -> (u128, u128, u128) {
        println!("a={}", a);
        println!("b={}", b);
        let (mut old_r, mut r) = (a, b);
        let (mut old_s, mut s) = (1, 0);
        let (mut old_t, mut t) = (0, 1);

        while r != 0 {
            let quotient = old_r / r;
            println!("quotient={:?}", quotient);
            old_r = old_r - quotient * r;
            std::mem::swap(&mut old_r, &mut r);
            old_s = old_s - quotient * s;
            std::mem::swap(&mut old_s, &mut s);
            old_t = old_t - quotient * t;
            std::mem::swap(&mut old_t, &mut t);
        }
        if old_s < 0 {
            old_s = old_s + b
        }

        (old_s as u128, old_t as u128, old_r as u128)
    }

    // Rustで演算子オーバーロードを行う
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
}
// テスト
fn main() {
    let field = modulus::Field { p: 11 }; // 素数 p = 7 での有限体
    let a = modulus::FieldElement { value: 8, field };
    let b = modulus::FieldElement { value: 5, field };

    let sum = a + b;
    let product = a * b;
    let difference = a - b;
    let quotient = a / b;
    let neg_a = -a;
    println!("1{:?}", a);
    let inv_a = a.inverse();
    println!("2{:?}", a);
    let pow_a = a ^ 3u128; // a^3

    println!("a + b = {:?}", sum);
    println!("a * b = {:?}", product);
    println!("a - b = {:?}", difference);
    println!("a / b = {:?}", quotient);
    println!("-a = {:?}", neg_a);
    println!("inverse of a = {:?}", inv_a);
    println!("a ^ 3 = {:?}", pow_a);
}
