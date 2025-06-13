use std::ops::{Add, Sub, Mul, Div, Neg, Rem};
use std::fmt;
use std::collections::HashSet;

use crate::modulus;
use modulus::FieldElement;

#[derive(Debug, Clone, PartialEq)]
pub struct Polynomial {
    pub coefficients: Vec<FieldElement>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<FieldElement>) -> Self {
        // 係数ベクトルの正規化
        let coefficients = Polynomial::trim(coefficients);
        Polynomial { coefficients }
    }

    // 係数ベクトルの正規化
    pub fn trim(mut coeffs: Vec<FieldElement>) -> Vec<FieldElement> {
        while let Some(true) = coeffs.last().map(|c| c.is_zero()) {
            coeffs.pop();
        }
        coeffs
}
    // 係数ベクトルの長さを取得
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
            value = &value + &(c * &xi);
            xi = &xi * point;
        }
        value
    }

    pub fn evaluate_domain(&self, domain: &[FieldElement]) -> Vec<FieldElement> {
        domain.iter().map(|d| self.evaluate(d)).collect()
    }

    pub fn add(&self, other: &Polynomial) -> Polynomial {
        if self.is_zero() {
            return other.clone();
        } else if other.is_zero() {
            return self.clone();
        }
        let field = self.coefficients[0].field;
        let max_len = usize::max(self.coefficients.len(), other.coefficients.len());
        let mut coeffs = vec![field.zero(); max_len];

        for i in 0..self.coefficients.len() {
            coeffs[i] = &coeffs[i] + &self.coefficients[i];
        }
        for i in 0..other.coefficients.len() {
            coeffs[i] = &coeffs[i] + &other.coefficients[i];
        }

        coeffs = Polynomial::trim(coeffs);
        Polynomial::new(coeffs)
    }

    pub fn substract(&self, other: &Polynomial) -> Polynomial {
        self.add(&other.neg())
    }

    pub fn multiply(&self, other: &Polynomial) -> Polynomial {
        if self.coefficients.is_empty() || other.coefficients.is_empty() {
            return Polynomial { coefficients: vec![] };
        }

        let zero = self.coefficients[0].field.zero();
        let mut buf = vec![zero; self.coefficients.len() + other.coefficients.len() - 1];

        for i in 0..self.coefficients.len() {
            if self.coefficients[i].is_zero() {
                continue;
            }
            for j in 0..other.coefficients.len() {
                buf[i + j] = &buf[i + j] + &(&self.coefficients[i] * &other.coefficients[j]);
            }
        }

        Polynomial { coefficients: buf }
    }

    pub fn neg(&self) -> Polynomial {
        Polynomial::new(self.coefficients.iter().map(|c| -c).collect())
    }

    pub fn divide(numerator: &Polynomial, denominator: &Polynomial) -> (Polynomial, Polynomial) {
        assert!(!denominator.is_zero(), "cannot divide by zero polynomial");
        if numerator.is_zero() {
            return (Polynomial::new(vec![]), Polynomial::new(vec![]));
        }

        let field = numerator.coefficients[0].field;
        let mut remainder = numerator.clone();
        let mut quotient = Polynomial::new(vec![field.zero(); numerator.coefficients.len()]);
        let denom_lead_inv = denominator.leading_coefficient().inverse();

        while remainder.degree() >= denominator.degree() && !remainder.is_zero() {
            let deg_diff = (remainder.degree() - denominator.degree()) as usize;
            let scale = &(remainder.leading_coefficient()) * &denom_lead_inv;
            let mut term_coeffs = vec![field.zero(); deg_diff];
            term_coeffs.push(scale);
            let term = Polynomial::new(term_coeffs);
            quotient = quotient.add(&term);
            remainder = (&remainder).sub(&term.mul(denominator));
        }

        (quotient, remainder)
    }
    pub fn pow(&self, exponent: u128) -> Self {
        if self.is_zero() {
            return Polynomial::new(vec![]);
        }
        if exponent == 0 {
            return Polynomial::new(vec![self.coefficients[0].field.one()]);
        }

        let mut acc = Polynomial::new(vec![self.coefficients[0].field.one()]);
        let mut base = self.clone();
        let mut exp = exponent;

        while exp > 0 {
            if exp & 1 == 1 {
                acc = &acc * &base;
            }
            base = &base * &base;
            exp >>= 1;
        }

        acc
    }

    pub fn interpolate_domain(domain: &[FieldElement], values: &[FieldElement]) -> Polynomial {
        assert_eq!(domain.len(), values.len());
        assert!(!domain.is_empty());
        let mut seen = HashSet::new();
        for x in domain {
            assert!(seen.insert(x.value), "Duplicate x in domain: {}", x.value);
        }
    
        let field = domain[0].field;
        let mut result = Polynomial::new(vec![field.zero()]);
    
        for (i, &xi) in domain.iter().enumerate() {
            let mut numerator = Polynomial::new(vec![field.one()]);
            let mut denominator = field.one();
    
            for (j, &xj) in domain.iter().enumerate() {
                if i == j {
                    continue;
                }
    
                // (x - xj)
                let term = Polynomial::new(vec![xj.neg(), field.one()]);
                numerator = &numerator * &term;
    
                // (xi - xj)
                denominator = &denominator * &(&xi - &xj);
            }
    
            // li(x) = Π(x - xj) / (xi - xj)
            let li = numerator.scalar(&(denominator.inverse()));
    
            // add li(x) * yi
            let term = li.scalar(&values[i]);
            result = &result + &term;
        }
        result
    }
    

    pub fn zerofier_domain(domain: &[FieldElement]) -> Polynomial {
        assert!(!domain.is_empty());
        let field = domain[0].field;
        let x = Polynomial::new(vec![field.zero(), field.one()]);
        let mut acc = Polynomial::new(vec![field.one()]);
        for d in domain {
            acc = &acc * &(&x - &Polynomial::new(vec![*d]))
        }
        acc
    }

    pub fn scale(&self, factor: &FieldElement) -> Polynomial {
        Polynomial::new(
            self.coefficients
                .iter()
                .enumerate()
                .map(|(i, c)| &factor.pow(i as u128) * c)
                .collect(),
        )
    }
    pub fn scalar(&self, factor: &FieldElement) -> Polynomial {
        Polynomial::new(
            self.coefficients
                .iter()
                .map(|c| c * factor)
                .collect(),
        )
    }

    
}

impl<'a, 'b> Add<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;
    fn add(self, rhs: &'b Polynomial) -> Polynomial {
        self.add(rhs)
    }
}

impl<'a, 'b> Sub<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;
    fn sub(self, rhs: &'b Polynomial) -> Polynomial {
        self.substract(rhs)
    }
}

impl<'a> Neg for &'a Polynomial {
    type Output = Polynomial;
    fn neg(self) -> Polynomial {
        self.neg()
    }
}

impl<'a, 'b> Mul<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: &'b Polynomial) -> Polynomial {
        self.multiply(rhs)
    }
}

impl<'a, 'b> Div<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;
    fn div(self, rhs: &'b Polynomial) -> Polynomial {
        let (quo, rem) = Polynomial::divide(self, rhs);
        assert!(rem.is_zero(), "cannot perform polynomial division because remainder is not zero");
        quo
    }
}

impl<'a, 'b> Rem<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;

    fn rem(self, rhs: &'b Polynomial) -> Polynomial {
        let (_quotient, remainder) = Polynomial::divide(self, rhs);
        remainder
    }
} 
impl fmt::Display for Polynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        let mut terms = vec![];
        for (i, coeff) in self.coefficients.iter().enumerate() {
            if coeff.is_zero() {
                continue;
            }
            let term = match i {
                0 => format!("{}", coeff.value),
                1 => format!("{}x", coeff.value),
                _ => format!("{}x^{}", coeff.value, i),
            };
            terms.push(term);
        }
        write!(f, "{}", terms.join(" + "))
    }
}
pub fn ntt(a: &mut Vec<FieldElement>, omega: FieldElement) {
    let n = a.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;

        if i < j {
            a.swap(i, j);
        }
    }

    let mut len = 2;
    while len <= n {
        let wlen = omega.pow((a[0].field.p - 1) / len as u128);
        for i in (0..n).step_by(len) {
            let mut w = FieldElement::new(1, a[0].field);
            for j in 0..len / 2 {
                let u = a[i + j];
                let v = &a[i + j + len / 2] * &w;
                a[i + j] = &u + &v;
                a[i + j + len / 2] = &u - &v;
                w = &w * &wlen;
            }
        }
        len <<= 1;
    }
}
pub fn intt(a: &mut Vec<FieldElement>, omega_inv: FieldElement) {
    let n = a.len();
    ntt(a, omega_inv);  // 再利用できる
    let n_inv = FieldElement::new(n as u128, a[0].field).inverse();
    for i in 0..n {
        a[i] = &a[i] * &n_inv;
    }
}


// テスト
#[cfg(test)]
mod tests {
    use serde::de::value;

    use super::*;
    use crate::modulus::FieldElement;
    use crate::modulus::Field;

    #[test]
    fn test_polynomial_add() {
        let p = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field: Field = Field{p}; 
        // f(x) = x^2 + 2x + 1
        let p1 = Polynomial::new(vec![field.one(), field.zero(), field.one()]); 
        // g(x) = x + 1
        let p2 = Polynomial::new(vec![field.one(), field.one()]);
        let result = &p1 + &p2;
        // f(x) + g(x) = 1 + 2x + 1x^2 + 1x + 1 = 2 + 3x + 1x^2
        assert_eq!(result.coefficients, vec![FieldElement::new(2, field), field.one(), field.one()]);
    }

    #[test]
    fn test_polynomial_sub() {
        let p = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field: Field = Field{p}; // (2^128) - 45 * (2^40) + 1

        // 計算結果が負数になる場合のテスト
        // f(x) = 0 + 1x + 1x^2
        let p1 = Polynomial::new(vec![field.zero(), field.one(), field.one()]); 
        // g(x) = 1 
        let p2 = Polynomial::new(vec![field.one()]); 
        let result = &p1 - &p2;
        // f(x) - g(x) = 0 + 1x + 1x^2 - 1 = p-1 + 1x + 1x^2
        assert_eq!(result.coefficients, vec![FieldElement::new(p-1, field), field.one(), field.one()]); 

        // 末尾のゼロ係数を削除するテスト
        // f(x) = 1 + 0x + 1x^2
        let p1 = Polynomial::new(vec![field.one(), field.one(), field.one()]); 
        // g(x) = 1 + 1x
        let p2 = Polynomial::new(vec![field.one(), field.one(), field.one()]); 
        let result = &p1 - &p2;
        assert_eq!(result.coefficients, vec![]); // 0
    }
    #[test]
    fn test_polynomial_mul() {
        let p = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field: Field = Field{p}; 
        // 片方がゼロの多項式の場合
        let p1 = Polynomial::new(vec![]); // 0
        let p2 = Polynomial::new(vec![field.one(), field.one()]); // 1 + 1x
        let result = &p1 * &p2;
        assert_eq!(result.coefficients, vec![]); // 0
        // 計算結果が法pを超える場合のテスト
        // f(x) = p-1 + 1x
        let p1 = Polynomial::new(vec![FieldElement::new(p-1, field), field.one()]); 
        // g(x) = 2 + 1x
        let p2 = Polynomial::new(vec![FieldElement::new(2, field), field.one()]); 
        let result = &p1 * &p2;
        // f(x) * g(x) = (p-1)*2 + (p+1)x + 1x^2
        assert_eq!(result.coefficients, 
                   vec![FieldElement::new(p-2, field), FieldElement::new(1, field), FieldElement::new(1, field)]); 
    }
    #[test]
    // 割り切れる場合のテスト
    fn test_polynomial_div_no_reminder() {
        
        let p = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field: Field = Field{p}; 

        //  f(x) = x^2 + 2x + 1
        let p1 = Polynomial::new(vec![
            FieldElement::new(1, field),
            FieldElement::new(2, field),
            FieldElement::new(1, field),
        ]);
        //  g(x) = x + 1
        let p2 = Polynomial::new(vec![
            FieldElement::new(1, field),
            FieldElement::new(1, field),
        ]);
        // f(x) / g(x) = x + 1, remainder = 0
        let (quotient, remainder) = Polynomial::divide(&p1, &p2);
        let expected_quotient = Polynomial::new(vec![
            FieldElement::new(1, field),
            FieldElement::new(1, field),
        ]);
        let expected_remainder = Polynomial::new(vec![]); // 0
        assert_eq!(quotient, expected_quotient);
        assert_eq!(remainder, expected_remainder);
    }
    #[test]
    // 割り切れない場合のテスト
    fn test_divide_with_remainder() {
        let p = 340282366920938463463374557953744961537;
        let field = Field { p };
    
        // f(x) = x^2 + 1
        let numerator = Polynomial::new(vec![
            FieldElement::new(1, field), // +1
            FieldElement::new(0, field), // 0x
            FieldElement::new(1, field), // +1x^2
        ]);
    
        // g(x) = x + 1
        let denominator = Polynomial::new(vec![
            FieldElement::new(1, field),
            FieldElement::new(1, field),
        ]);
    
        // f / g は割り切れない（余りが非ゼロ）
        let (quotient, remainder) = Polynomial::divide(&numerator, &denominator);
    
        // f = (x - 1)(x + 1) + 2, so expected remainder is 2
        let expected_remainder = Polynomial::new(vec![
            FieldElement::new(2, field)
        ]);
    
        assert!(!remainder.is_zero());
        assert_eq!(&(&quotient * &denominator) + &remainder, numerator);
    }
    #[test]
    fn test_divide_zero_numerator() {
        let p = 340282366920938463463374557953744961537;
        let field = Field { p };
    
        let zero_poly = Polynomial::new(vec![]); // 0
        let divisor = Polynomial::new(vec![
            FieldElement::new(1, field),
            FieldElement::new(1, field),
        ]); // x + 1
    
        let (quotient, remainder) = Polynomial::divide(&zero_poly, &divisor);
    
        assert_eq!(quotient, Polynomial::new(vec![])); // 0
        assert_eq!(remainder, Polynomial::new(vec![])); // 0
    }
    #[test]
    fn test_polynomial_pow() {
        let p = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field: Field = Field{p}; 
        // f(x) = x + 1
        let p1 = Polynomial::new(vec![field.one(), field.one()]); 
        let result = &p1.pow(2);
        // f(x)^2 = x^2 + 2x + 1
        assert_eq!(result.coefficients, vec![field.one(), FieldElement::new(2, field), field.one()]); 
    }
    #[test]
    fn test_evaluate() {
        let p = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field: Field = Field{p}; 
        // f(x) = x^2 + x + 1
        let p1 = Polynomial::new(vec![field.one(), field.one(), field.one()]); 
        // x = 2
        let x = FieldElement::new(2, field);
        let result = p1.evaluate(&x);
        // f(2) = 2^2 + 2*2 + 1 = 9
        assert_eq!(result, FieldElement::new(7, field)); 
    }
    #[test]
    fn test_evaluate_domain() {
        let p = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field: Field = Field{p}; 
        // f(x) = x^2 + x + 1
        let p1 = Polynomial::new(vec![field.one(), field.one(), field.one()]); 
        // x = 2, 4
        let w = FieldElement::new(2, field);
        let w2 = w^2;
        let result = p1.evaluate_domain(&[w, w2]);
        // f(2) = 7, g(4) = 5
        assert_eq!(result, vec![FieldElement::new(7, field), FieldElement::new(21, field)]); 
    }
    #[test]
    fn test_zerofier_domain() {
        let p = 340282366920938463463374557953744961537;
        let field = Field { p };
    
        // domain = [1, 2]
        let d1 = FieldElement::new(1, field);
        let d2 = FieldElement::new(2, field);
        let domain = vec![d1, d2];
    
        let z = Polynomial::zerofier_domain(&domain);
    
        // Z(x) = (x - 1)(x - 2) = x^2 - 3x + 2
        let minus3 = FieldElement::new(p - 3, field); // -3 mod p
        let expected = Polynomial::new(vec![
            FieldElement::new(2, field),    // constant
            minus3,                         // -3x
            FieldElement::new(1, field),    // x^2
        ]);
    
        assert_eq!(z, expected);
    
        // Also verify that Z(d1) = 0 and Z(d2) = 0
        for d in domain {
            assert_eq!(z.evaluate(&d), field.zero());
        }
    }
    #[test]
    fn test_polynomial_scale() {
        let p = 340282366920938463463374557953744961537;
        let field = Field { p };

        let one = FieldElement::new(1, field);
        let two = FieldElement::new(2, field);
        let three = FieldElement::new(3, field);
        let factor = FieldElement::new(2, field);

        // f(x) = 1 + 2x + 3x^2
        let poly = Polynomial::new(vec![one, two, three]);

        // scale by factor=2:
        // new coefficients:
        // [1 * 2^0, 2 * 2^1, 3 * 2^2] = [1, 4, 12]
        let scaled = poly.scale(&factor);

        let expected = Polynomial::new(vec![
            FieldElement::new(1, field),
            FieldElement::new(4, field),
            FieldElement::new(12, field),
        ]);

        assert_eq!(scaled, expected);
    }

    #[test]
    fn test_interpolate_domain() {
        let p = 340282366920938463463374557953744961537;
        let field = Field { p };
        // f(x) = x^2 + 1
        let x0 = FieldElement::new(1, field);
        let x1 = FieldElement::new(2, field);
        let x2 = FieldElement::new(3, field);
        let domain = vec![x0, x1, x2];

        let y0 = FieldElement::new(2, field); // 1^2 + 1 = 2
        let y1 = FieldElement::new(5, field); // 2^2 + 1 = 5
        let y2 = FieldElement::new(10, field); // 3^2 + 1 = 10
        let values = vec![y0, y1, y2];

        let poly = Polynomial::interpolate_domain(&domain, &values);
        assert_eq!(poly.evaluate(&x0), y0);
        assert_eq!(poly.evaluate(&x1), y1);
        assert_eq!(poly.evaluate(&x2), y2);
    }
    #[test]
    fn test_interpolate_domain_2() {
        let p = 340282366920938463463374557953744961537;
        let field = Field { p };

        let x0 = FieldElement::new(83737537015097400980107252073087094973, field);
        let x1 = FieldElement::new(79815460479162102507501624458750315529, field);
        let x2 = FieldElement::new(274096143417777972126522437806823942815, field);
        let domain = vec![x0, x1, x2];

        let y0 = FieldElement::new(6561, field); 
        let y1 = FieldElement::new(156675582141191514785497108581527433323, field); 
        let y2 = FieldElement::new(39005479933400821706556350017912709322, field);
        let values = vec![y0, y1, y2];

        let poly = Polynomial::interpolate_domain(&domain, &values);
        assert_eq!(poly.evaluate(&x0), y0);
        assert_eq!(poly.evaluate(&x1), y1); // 1を加えると値が変わる
        assert_eq!(poly.evaluate(&x2), y2);
    }
}