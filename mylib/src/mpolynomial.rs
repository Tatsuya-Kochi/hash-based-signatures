use std::collections::{BTreeMap, HashMap};
use crate::modulus::{FieldElement, Field};
use crate::polynomial::Polynomial;
use std::ops::{Add, Sub, Mul, Neg};

#[derive(Debug, Clone, PartialEq)]
pub struct MPolynomial {
    // keyはf(x)、valueはx  制約の構造：[[レジスタのインデックス, 累乗], 係数]
    pub dictionary: HashMap<BTreeMap<usize, usize>, FieldElement>, 
}

impl MPolynomial {
    pub fn new(dictionary: HashMap<BTreeMap<usize, usize>, FieldElement>) -> Self {
        Self { dictionary }
    }

    pub fn zero() -> Self {
        Self { dictionary: HashMap::new() }
    }

    pub fn constant(element: FieldElement) -> Self {
        let mut dict = HashMap::new();
        let btree = BTreeMap::new();
        dict.insert(btree, element);
        Self::new(dict)
    }

    pub fn add(&self, other: &MPolynomial) -> MPolynomial {
        let mut result = self.dictionary.clone();

        for (k, v) in &other.dictionary {
            // k は BTreeMap<usize, usize>
            let entry = result.entry(k.clone()).or_insert(v.field.zero());
            *entry = &*entry + v;
        }

        MPolynomial { dictionary: result }
    }

    pub fn substract(&self, other: &MPolynomial) -> MPolynomial {
        let mut result = self.dictionary.clone();

        for (k, v) in &other.dictionary {
            let entry = result.entry(k.clone()).or_insert(v.field.zero());
            *entry = &*entry - v;
        }

        MPolynomial { dictionary: result }
    }

    pub fn negate(&self) -> MPolynomial {
        let mut result = HashMap::new();

        for (key, value) in &self.dictionary {
            result.insert(key.clone(), -value);
        }

        MPolynomial { dictionary: result }
    }
    
    pub fn multiply(&self, rhs: &MPolynomial) -> MPolynomial {
        if self.is_zero() || rhs.is_zero() {
            return Self::zero(); // 型メソッドの明示
        }
    
        let mut result = HashMap::new();
    
        for (k0, v0) in &self.dictionary {
            for (k1, v1) in &rhs.dictionary {
                // 単項の指数を加算
                let mut exp = k0.clone();
                for (var_idx, degree) in k1 {
                    *exp.entry(*var_idx).or_insert(0) += *degree;
                }
    
                let entry = result.entry(exp).or_insert(v0.field.zero());
                *entry = &*entry + &(v0 * v1);
            }
        }
        MPolynomial { dictionary: result }
    }
    /*pub fn from_var(i: usize) -> Self {
        let mut dict = HashMap::new();
        dict.insert(vec![i], FieldElement::one());
        Self::new(dict)
    } */

    /*pub fn from_next_var(i: usize, offset: usize) -> Self {
        let mut dict = HashMap::new();
        dict.insert(vec![i + offset], FieldElement::one());
        Self::new(dict)
    } */

   // 係数が0
    pub fn is_zero(&self) -> bool {
        self.dictionary.values().all(|v| v.is_zero())
    }

    // x_0, x_1, ..., x_n の変数を持つ多項式を生成
    // 変数の数は num_variables で指定
    // 各変数の係数は 1
    pub fn variables(&self, num_variables: usize, field: Field) -> Vec<Self> {
        let mut result = Vec::new();

        for i in 0..num_variables {
            let mut exponents = BTreeMap::new();
            exponents.insert(i, 1); // 変数 i の次数 = 1

            let mut dict = HashMap::new();
            dict.insert(exponents, field.one()); // 係数 1 を設定

            result.push(Self { dictionary: dict });
        }
        result
    }

    // 変数の数は variable_index + 1
    // variable_index は変数のインデックスを指定 おそらく1から始まる
    pub fn lift(&self, polynomial: &Polynomial, variable_index: usize) -> Self {
        if polynomial.is_zero() {
            return Self::zero();
        }

        let field = polynomial.coefficients[0].field;
        let variables = self.variables(variable_index + 1, field);
        let x = &variables[variable_index];
        let mut acc = Self::zero();

        for (i, coeff) in polynomial.coefficients.iter().enumerate() {
            let term = &Self::constant(*coeff) * &x.pow(i as u128);
            acc = &acc + &term;
        }
        acc
    }

    pub fn evaluate(&self, point: &[FieldElement]) -> FieldElement {
        let mut acc = point[0].field.zero();

        for (monomial, coeff) in &self.dictionary {
            let mut prod = *coeff;

            for (var_index, exponent) in monomial {
                prod = &prod * &point[*var_index].pow(*exponent as u128);
            }

            acc = &acc + &prod;
        }

        acc
    }

    pub fn evaluate_symbolic(&self, point: &[Polynomial]) -> Polynomial {
        let mut acc = Polynomial::new(vec![]); // 初期値はゼロ多項式

        for (monomial, coeff) in &self.dictionary {
            let mut prod = Polynomial::new(vec![*coeff]); // 係数から開始

            for (var_index, exponent) in monomial {
                let term = point[*var_index].clone().pow(*exponent as u128);
                prod = &prod * &term;
            }

            acc = &acc + &prod;
        }

        acc
    }

    pub fn pow(&self, exponent: u128) -> Self {
        if exponent == 0 {
            let field = self.dictionary.values().next().unwrap().field;
            return Self::constant(field.one());
        }

        if self.is_zero() {
            return Self::zero();
        }

        let mut acc = Self::constant(
            self.dictionary.values().next().unwrap().field.one(),
        );
        let mut base = self.clone();
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
    pub fn scale_polynomial(poly: &MPolynomial, scalar: &FieldElement) -> MPolynomial {
        let scaled_terms = poly.dictionary
            .iter()
            .map(|(monomial, coeff)| (monomial.clone(), coeff * scalar))
            .collect();
    
        MPolynomial { dictionary: scaled_terms }
    }
    
}

impl<'a, 'b> Add<&'b MPolynomial> for &'a MPolynomial {
    type Output = MPolynomial;
    fn add(self, rhs: &'b MPolynomial) -> MPolynomial {
        self.add(rhs)
    }
}

impl<'a, 'b> Sub<&'b MPolynomial> for &'a MPolynomial {
    type Output = MPolynomial;
    fn sub(self, rhs: &'b MPolynomial) -> MPolynomial {
        self.substract(rhs)
    }
}

impl<'a> Neg for &'a MPolynomial {
    type Output = MPolynomial;
    fn neg(self) -> MPolynomial {
        let mut dict = HashMap::new();
        for (k, v) in &self.dictionary {
            dict.insert(k.clone(), -v);
        }
        MPolynomial { dictionary: dict }
    }
}

impl<'a, 'b> Mul<&'b MPolynomial> for &'a MPolynomial {
    type Output = MPolynomial;
    fn mul(self, rhs: &'b MPolynomial) -> MPolynomial {
        self.multiply(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modulus::Field;

    #[test]
    fn test_mpolynomial_add() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};
        let mut dict1 = HashMap::new();

        // 3x → {0: 1}
        let mut mono1 = BTreeMap::new();
        mono1.insert(0, 1);
        dict1.insert(mono1, FieldElement::new(3, field));

        // 2xy → {0: 1, 1: 1}
        let mut mono2 = BTreeMap::new();
        mono2.insert(0, 1);
        mono2.insert(1, 1);
        dict1.insert(mono2, FieldElement::new(2, field));

        // 5y² → {1: 2}
        let mut mono3 = BTreeMap::new();
        mono3.insert(1, 2);
        dict1.insert(mono3, FieldElement::new(5, field));

        // 5y^2 + 3x + 2xy
        let mpoly1 = MPolynomial::new(dict1);

        let mut dict2 = HashMap::new();
        // 4x → {0: 1}
        let mut mono4 = BTreeMap::new();
        mono4.insert(0, 1);
        dict2.insert(mono4, FieldElement::new(4, field));
        // 3xy → {0: 1, 1: 1}
        let mut mono5 = BTreeMap::new();
        mono5.insert(0, 1);
        mono5.insert(1, 1);
        dict2.insert(mono5, FieldElement::new(3, field));
        // 2y² → {1: 2}
        let mut mono6 = BTreeMap::new();
        mono6.insert(1, 2);
        dict2.insert(mono6, FieldElement::new(2, field));
        // 2y^2 + 4x + 3xy
        let mpoly2 = MPolynomial::new(dict2);

        assert_eq!(&mpoly1+&mpoly2, 
            MPolynomial::new({
                let mut dict = HashMap::new();

                // 5xy → {0: 1, 1: 1}
                let mut mono2 = BTreeMap::new();
                mono2.insert(0, 1);
                mono2.insert(1, 1);
                dict.insert(mono2, FieldElement::new(5, field));

                // 7x → {0: 1}
                let mut mono1 = BTreeMap::new();
                mono1.insert(0, 1);
                dict.insert(mono1, FieldElement::new(7, field));

                // 7y² → {1: 2}
                let mut mono3 = BTreeMap::new();
                mono3.insert(1, 2);
                dict.insert(mono3, FieldElement::new(7, field));

                dict
            })
        );
    }
    #[test]
    fn test_mpolynomial_sub() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};
        let mut dict1 = HashMap::new();

        // 3x → {0: 1}
        let mut mono1 = BTreeMap::new();
        mono1.insert(0, 1);
        dict1.insert(mono1, FieldElement::new(3, field));

        // 2xy → {0: 1, 1: 1}
        let mut mono2 = BTreeMap::new();
        mono2.insert(0, 1);
        mono2.insert(1, 1);
        dict1.insert(mono2, FieldElement::new(2, field));

        // 5y² → {1: 2}
        let mut mono3 = BTreeMap::new();
        mono3.insert(1, 2);
        dict1.insert(mono3, FieldElement::new(5, field));

        // 5y^2 + 3x + 2xy
        let mpoly1 = MPolynomial::new(dict1);

        let mut dict2 = HashMap::new();
        // 4x → {0: 1}
        let mut mono4 = BTreeMap::new();
        mono4.insert(0, 1);
        dict2.insert(mono4, FieldElement::new(4, field));
        // 3xy → {0: 1, 1: 1}
        let mut mono5 = BTreeMap::new();
        mono5.insert(0, 1);
        mono5.insert(1, 1);
        dict2.insert(mono5, FieldElement::new(3, field));
        // 2y² → {1: 2}
        let mut mono6 = BTreeMap::new();
        mono6.insert(1, 2);
        dict2.insert(mono6, FieldElement::new(2, field));
        // 2y^2 + 4x + 3xy
        let mpoly2 = MPolynomial::new(dict2);

        assert_eq!(&mpoly1-&mpoly2,
            MPolynomial::new({
                let mut dict = HashMap::new();
                // -1xy → {0: 1, 1: 1}
                let mut mono2 = BTreeMap::new();
                mono2.insert(0, 1);
                mono2.insert(1, 1);
                dict.insert(mono2, FieldElement::new(p-1, field));
                // -1x → {0: 1}
                let mut mono1 = BTreeMap::new();
                mono1.insert(0, 1);
                dict.insert(mono1, FieldElement::new(p-1, field));
                // 3y² → {1: 2}
                let mut mono3 = BTreeMap::new();
                mono3.insert(1, 2);
                dict.insert(mono3, FieldElement::new(3, field));
                dict
            }
        ));
    }
    #[test]
    fn test_mpolynomial_negate() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};
        let mut dict = HashMap::new();

        // 3x → {0: 1}
        let mut mono1 = BTreeMap::new();
        mono1.insert(0, 1);
        dict.insert(mono1, FieldElement::new(3, field));

        // 2xy → {0: 1, 1: 1}
        let mut mono2 = BTreeMap::new();
        mono2.insert(0, 1);
        mono2.insert(1, 1);
        dict.insert(mono2, FieldElement::new(2, field));

        // 5y² → {1: 2}
        let mut mono3 = BTreeMap::new();
        mono3.insert(1, 2);
        dict.insert(mono3, FieldElement::new(5, field));

        // 5y^2 + 3x + 2xy
        let mpoly = MPolynomial::new(dict);

        assert_eq!(-&mpoly,
            MPolynomial::new({
                let mut dict_neg = HashMap::new();
                // -3x → {0: 1}
                let mut mono_neg1 = BTreeMap::new();
                mono_neg1.insert(0, 1);
                dict_neg.insert(mono_neg1, FieldElement::new(p-3, field));
                // -2xy → {0: 1, 1: 1}
                let mut mono_neg2 = BTreeMap::new();
                mono_neg2.insert(0, 1);
                mono_neg2.insert(1, 1);
                dict_neg.insert(mono_neg2, FieldElement::new(p-2, field));
                // -5y² → {1: 2}
                let mut mono_neg3 = BTreeMap::new();
                mono_neg3.insert(1, 2);
                dict_neg.insert(mono_neg3, FieldElement::new(p-5, field));
                dict_neg
            })
        );
    }
    #[test]
    fn test_mpolynomial_mul() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};
        let mut dict1 = HashMap::new();

        // 3x → {0: 1}
        let mut mono1 = BTreeMap::new();
        mono1.insert(0, 1);
        dict1.insert(mono1, FieldElement::new(3, field));

        // 2xy → {0: 1, 1: 1}
        let mut mono2 = BTreeMap::new();
        mono2.insert(0, 1);
        mono2.insert(1, 1);
        dict1.insert(mono2, FieldElement::new(2, field));

        // 3x + 2xy
        let mpoly1 = MPolynomial::new(dict1);

        let mut dict2 = HashMap::new();
        
        // 3xy → {0: 1, 1: 1}
        let mut mono5 = BTreeMap::new();
        mono5.insert(0, 1);
        mono5.insert(1, 1);
        dict2.insert(mono5, FieldElement::new(3, field));
        // 2y² → {1: 2}
        let mut mono6 = BTreeMap::new();
        mono6.insert(1, 2);
        dict2.insert(mono6, FieldElement::new(2, field));
        // 2y^2 + 3xy
        let mpoly2 = MPolynomial::new(dict2);

        // 9x^2y + 6xy^2 + 4xy^3 + 6x^2y^2
        assert_eq!(&mpoly1*&mpoly2,
            MPolynomial::new({
                let mut dict = HashMap::new();
                // 9x²y → {0: 2, 1: 1}
                let mut mono1 = BTreeMap::new();
                mono1.insert(0, 2);
                mono1.insert(1, 1);
                dict.insert(mono1, FieldElement::new(9, field));
                // 6xy² → {0: 1, 1: 2}
                let mut mono2 = BTreeMap::new();
                mono2.insert(0, 1);
                mono2.insert(1, 2);
                dict.insert(mono2, FieldElement::new(6, field));
                // 4xy^3 → {0: 1, 1: 3}
                let mut mono3 = BTreeMap::new();
                mono3.insert(0, 1);
                mono3.insert(1, 3);
                dict.insert(mono3, FieldElement::new(4, field));
                // 6x^2y^2 → {0: 2, 1: 2}
                let mut mono4 = BTreeMap::new();
                mono4.insert(0, 2);
                mono4.insert(1, 2);
                dict.insert(mono4, FieldElement::new(6, field));
                dict
            })
        );
    }
    #[test]
    fn test_variables() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};
        let mpoly = MPolynomial::zero();
        let variables = mpoly.variables(3, field);

        assert_eq!(variables.len(), 3);
        assert_eq!(variables[0].dictionary.len(), 1);
        assert_eq!(variables[1].dictionary.len(), 1);
        assert_eq!(variables[2].dictionary.len(), 1);
    }
    #[test]
    fn test_lift() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};
        let mpoly = MPolynomial::zero();
        let index = 2;
        // 1 + 2x
        let poly = Polynomial::new(vec![FieldElement::new(1, field), FieldElement::new(2, field)]);
        let lifted = mpoly.lift(&poly, index);

        assert_eq!(lifted, MPolynomial::new({
            let mut dict = HashMap::new();
            // 1
            let mut mono1 = BTreeMap::new();
            dict.insert(mono1, FieldElement::new(1, field));
            // 2x インデックスが変数に対応
            let mut mono2 = BTreeMap::new();
            mono2.insert(index, 1);
            dict.insert(mono2, FieldElement::new(2, field));

            dict
            })
        );
    }
    #[test]
    fn test_mpolynomial_evaluate() {
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field{p};
        let points = [FieldElement::new(3, field), FieldElement::new(2, field)];

        let mut dict = HashMap::new();
        let mut mono1 = BTreeMap::new();
        mono1.insert(0, 2);
        // 5x^2
        dict.insert(mono1, FieldElement::new(5, field));
        let mut mono2 = BTreeMap::new();
        // 10y^2
        mono2.insert(1, 2);
        dict.insert(mono2, FieldElement::new(10, field));

        let mpoly = MPolynomial::new(dict);

        assert_eq!(mpoly.evaluate(&points), FieldElement::new(85, field))
    }
    #[test]
    fn test_mpolynomial_evaluate_symbolic() {
        let p = 340282366920938463463374557953744961537; // 大きな素数
        let field = Field { p };

        // 係数
        let f3 = FieldElement::new(3, field);
        let f2 = FieldElement::new(2, field);
        let f5 = FieldElement::new(5, field);

        // MPolynomial f(x, y) = 3x + 2xy + 5y²
        let mut dict = HashMap::new();

        // 3x → {0:1}
        let mut mono1 = BTreeMap::new();
        mono1.insert(0, 1);
        dict.insert(mono1, f3);

        // 2xy → {0:1, 1:1}
        let mut mono2 = BTreeMap::new();
        mono2.insert(0, 1);
        mono2.insert(1, 1);
        dict.insert(mono2, f2);

        // 5y² → {1:2}
        let mut mono3 = BTreeMap::new();
        mono3.insert(1, 2);
        dict.insert(mono3, f5);

        let mpoly = MPolynomial::new(dict);

        // 評価点 point = key:0(代数1) = 1 + x, key:1(代数2) = 2 + x
        let x_poly = Polynomial::new(vec![FieldElement::new(1, field), FieldElement::new(1, field)]); // 1 + x
        let y_poly = Polynomial::new(vec![FieldElement::new(2, field), FieldElement::new(1, field)]); // 1 + y
        let point = vec![x_poly, y_poly];

        // 評価結果を取得
        let result = mpoly.evaluate_symbolic(&point);

        // 期待される多項式：
        // 3*(1 + x) + 2*(1 + x)*(2 + x) + 5*(2 + x)^2
        // = 7x^2 + 29x + 27

        let expected = Polynomial::new(vec![
            FieldElement::new(27, field),     // 定数項
            FieldElement::new(29, field),      // x
            FieldElement::new(7, field),     // x^2
        ]);

        assert_eq!(result, expected);
    }
    fn test_mpolynomial_pow() {
        let p = 340282366920938463463374557953744961537;
        let field = Field { p };

        let mut dict1 = HashMap::new();
        let mut mono1 = BTreeMap::new();
        mono1.insert(0, 2);
        dict1.insert(mono1, FieldElement::new(5, field));
        let mpoly = MPolynomial::new(dict1);
        assert_eq!(mpoly, MPolynomial::new({
            let mut dict2 = HashMap::new();
            let mut mono2 = BTreeMap::new();
            mono2.insert(0, 4);
            dict2.insert(mono2, FieldElement::new(25, field));
            dict2
        }
        ));
    }
    #[test]
    fn test_transition_constraints(){
        let p: u128 = 340282366920938463463374557953744961537; // (2^128) - 45 * (2^40) + 1
        let field = Field::new(p);
        let mut dict1 = HashMap::new();
        dict1.insert([(2, 2)].into_iter().collect(), Field::one(field));
        let mut dict2 = HashMap::new();
        dict2.insert([(2, 1)].into_iter().collect(), Field::one(field));

        let diff_poly = &MPolynomial::new(dict1) - &MPolynomial::new(dict2);
        let constraint = MPolynomial::scale_polynomial(&diff_poly, &FieldElement::new(2, field));
                
        let expected = MPolynomial::new({
            let mut dict = HashMap::new();
            let mut mono1 = BTreeMap::new();
            mono1.insert(2, 2);
            dict.insert(mono1, FieldElement::new(2, field));
            let mut mono2 = BTreeMap::new();
            mono2.insert(2, 1);
            dict.insert(mono2, FieldElement::new(p-2, field));
            dict
        });
        assert_eq!(constraint, expected);
    }
}
