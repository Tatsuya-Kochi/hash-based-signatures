use std::ops::{Add, Sub, Mul, Div, Neg};

use crate::modulus;
use modulus::FieldElement;
use modulus::Field;

#[derive(Debug, Clone, PartialEq)]
pub struct Polynomial {
    coefficients: Vec<FieldElement>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<FieldElement>) -> Self {
        Polynomial { coefficients }
    }

    pub fn degree(&self) -> isize {
        if self.coefficients.is_empty() {
            return -1;
        }

        let zero = self.coefficients[0].field.zero();
        if self.coefficients.iter().all(|c| *c == zero) {
            return -1;
        }

        self.coefficients.iter().rposition(|&c| c != zero).unwrap() as isize
    }

    pub fn is_zero(&self) -> bool {
        self.degree() == -1
    }

    pub fn leading_coefficient(&self) -> FieldElement {
        self.coefficients[self.degree() as usize]
    }

    pub fn evaluate(&self, point: &FieldElement) -> FieldElement {
        let mut value = point.field.zero();
        let mut xi = point.field.one();

        for c in &self.coefficients {
            value = value + *c * xi; // ここでの `+` と `*` はオーバーロードされた演算子です
            xi = xi * *point; // フィールド要素の掛け算
        }

        value
    }

    pub fn evaluate_domain(&self, domain: Vec<FieldElement>) -> Vec<FieldElement> {
        domain.iter().map(|&d| self.evaluate(&d)).collect()
    }


    pub fn add(self, other: Polynomial) -> Polynomial {
        if self.degree() == -1{
            return other
        }
        else if other.degree() == -1{
            return self
        }
        let field = self.coefficients[0].field; // フィールドを取得

        // 長さが最大の方に合わせる
        let max_len = usize::max(self.coefficients.len(), other.coefficients.len());

        // 係数ベクタを初期化（ゼロ要素で埋める）
        let mut coeffs = vec![field.zero(); max_len];

        // selfの係数を追加
        for i in 0..self.coefficients.len() {
            coeffs[i] = coeffs[i] + self.coefficients[i].clone();
        }

        // otherの係数を追加
        for i in 0..other.coefficients.len() {
            coeffs[i] = coeffs[i] + other.coefficients[i].clone();
        }

        // 新しいPolynomialを返す
        Polynomial::new(coeffs)
    }

    pub fn sub(self, other: Polynomial) -> Polynomial {
        self.add(other.neg())
    }

    pub fn mul(&self, other: &Polynomial) -> Polynomial {
        if self.coefficients.is_empty() || other.coefficients.is_empty() {
            return Polynomial { coefficients: vec![] }; // 空の多項式を返す
        }

        let zero = self.coefficients[0].field.zero(); // ゼロのフィールド要素を取得
        let mut buf = vec![zero; self.coefficients.len() + other.coefficients.len() - 1];

        for i in 0..self.coefficients.len() {
            if self.coefficients[i].is_zero() {
                continue; // スパース多項式のための最適化
            }

            for j in 0..other.coefficients.len() {
                buf[i + j] = buf[i + j] + self.coefficients[i] * other.coefficients[j];
            }
        }

        Polynomial { coefficients: buf }
    }

    pub fn neg(&self) -> Polynomial {
        Polynomial::new(self.coefficients.iter().map(|c| -c.clone()).collect())
    }

    pub fn divide(numerator: &Polynomial, denominator: &Polynomial) -> (Polynomial, Polynomial) {
        // 省略：除算の実装
        unimplemented!()
    }

    pub fn interpolate_domain(domain: &[FieldElement], values: &[FieldElement]) -> Polynomial {
        assert!(domain.len() == values.len(), "number of elements in domain does not match number of values");
        assert!(domain.len() > 0, "cannot interpolate between zero points");

        let mut acc = Polynomial::new(vec![]);

        for i in 0..domain.len() {
            let mut prod = Polynomial::new(vec![values[i].clone()]);
            for j in 0..domain.len() {
                if j == i {
                    continue;
                }
                prod = prod * (Polynomial::new(vec![domain[i].clone()]) - Polynomial::new(vec![domain[j].clone()]));
                prod = prod * Polynomial::new(vec![(domain[i].clone() - domain[j].clone()).inverse()]);
            }
            acc = acc + prod;
        }

        acc
    }

    pub fn zerofier_domain(domain: &[FieldElement]) -> Polynomial {
        let field = domain[0].field;
        let x = Polynomial::new(vec![field.zero(), field.one()]);
        let mut acc = Polynomial::new(vec![field.one()]);
        for d in domain {
            acc = acc * (x.clone() - Polynomial::new(vec![d.clone()]));
        }
        acc
    }

    pub fn scale(&self, factor: &FieldElement) -> Polynomial {
        Polynomial::new(
            self.coefficients.iter()
                .enumerate()
                .map(|(i, c)| (factor.pow(i as u128) * *c).clone())
                .collect(),
        )
    }
}

// 演算子のオーバーロードを実装する
impl Add for Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Polynomial) -> Polynomial {
        self.add(rhs)
    }
}

impl Sub for Polynomial {
    type Output = Polynomial;
    fn sub(self, rhs: Polynomial) -> Polynomial {
        self.sub(rhs)
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    fn neg(self) -> Polynomial {
        // `FieldElement` のイテレータから Vec<FieldElement> に変換し、それを使って Polynomial を作成
        let negated_coefficients: Vec<FieldElement> = self.coefficients.iter().map(|c| -c.clone()).collect();
        
        // `Polynomial`のコンストラクタに`Vec<FieldElement>`を渡す
        Polynomial::new(negated_coefficients)
    }
}

impl Mul for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Polynomial) -> Polynomial {
        // 省略：掛け算のロジック
        unimplemented!()
    }
}

impl Div for Polynomial {
    type Output = Polynomial;

    fn div(self, other: Polynomial) -> Polynomial {
        let (quo, rem) = Polynomial::divide(&self, &other);
        assert!(rem.is_zero(), "cannot perform polynomial division because remainder is not zero");
        quo
    }
}