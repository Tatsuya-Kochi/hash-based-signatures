use crate::modulus::{FieldElement, Field};
use crate::matrix::Matrix;

pub struct AnemoiPermutation{
    pub p: u128, // prime
    pub alpha: u128,
    pub n_rounds: usize,
    pub n_cols: usize,
    pub security_level: usize,
    pub QUAD: usize, // assuming QUAD = 2
    pub g: FieldElement, // generator for the field
    pub beta: FieldElement, // generator for the field
    pub delta: FieldElement, // inverse of g
    pub alpha_inv: u128, // inverse of alpha in the field
    pub C: Vec<FieldElement>, // constant vector C
    pub D: Vec<FieldElement>, // constant vector D
    pub mat: Matrix, // MDS matrix
}

impl AnemoiPermutation {
    pub fn new(
        p: u128,
        alpha: u128,
        n_rounds: usize,
        n_cols: usize,
        security_level: usize,
    ) -> Self {
        let field = Field::new(p);
        let QUAD = 2; // assuming QUAD = 2
        let g = FieldElement::new(3, p); // generator for the field
        let beta = g;
        let delta = self.g**(-1); // assuming delta is the inverse of g
        let alpha_inv = self.alpha.pow(&[p - 2]); // inverse_mod(self.alpha, self.q-1)
        let C = vec![FieldElement::new(1, p); n_cols]; // constant vector C
        let D = vec![FieldElement::new(0, p); n_cols]; // constant vector D
        let mat = vec![vec![FieldElement::new(0, p); n_cols]; n_cols]; // MDS matrix placeholder
        AnemoiPermutation {
            p,
            alpha,
            n_rounds,
            n_cols,
            security_level,
            QUAD,
            g,
            beta,
            delta,
            alpha_inv,
            C,
            D,
            mat,
        }
    }

    pub fn input_size(&self) -> usize {
        2 * self.n_cols
    }

    pub fn evaluate_sbox(&self, x: FieldElement, y: FieldElement) -> &[FieldElement] {
        let mut x = x;
        let mut y = y;

        let mut y_quad = y^self.QUAD; // assuming QUAD = 2
        x = &x - &(&self.beta * &y_quad);
        let x_pow = x^self.alpha_inv;
        y = y - x_pow;
        let mut y_quad = y^self.QUAD; // assuming QUAD = 2
        x = &x + &(&(&self.beta * &y_quad) + &self.delta);

        [x, y]
    }

    pub fn linear_layer(&self, x: &[FieldElement], y: &[FieldElement]) -> (Vec<FieldElement>, Vec<FieldElement>) {
        let mut x = x.to_vec();
        let mut y = y.to_vec();
        // Apply the MDS matrix to x and y
        let x = self.mat.mul_vec(x);
        let mut y_shifted = y[1..].to_vec();
        y_shifted.push(y[0].clone());
        let mut y = self.mat.mul_vec(&y_shifted);

        for i in 0..self.n_cols {
            y[i] = &x[i] + &y[i];
            x[i] = &x[i] + &y[i];
        }
        (x, y)
    }

    pub fn eval_with_intermediate_values(&self, x: Vec<FieldElement>, y: Vec<FieldElement>) -> Vec<(Vec<FieldElement>, Vec<FieldElement>)> {
        let mut x = x.clone();
        let mut y = y.clone();
        let mut result = vec![(x.clone(), y.clone())];

        for r in 0..self.n_rounds {
            for i in 0..self.n_cols {
                x[i] = &x[i] + &self.c[r][i];
                y[i] = &y[i] + &self.d[r][i];
            }
            let (lx, ly) = self.linear_layer(x, y);
            x = lx;
            y = ly;
            for i in 0..self.n_cols {
                let (sx, sy) = self.evaluate_sbox(x[i].clone(), y[i].clone());
                x[i] = sx;
                y[i] = sy;
            }
            result.push((x.clone(), y.clone()));
        }

        // final linear layer
        let (lx, ly) = self.linear_layer(x, y);
        result.push((lx.clone(), ly.clone()));
        result
    }

    pub fn call(&self, input: Vec<FieldElement>) -> Vec<FieldElement> {
        if input.len() != self.input_size() {
            panic!("wrong input size!");
        }
        let x = input[..self.n_cols].to_vec();
        let y = input[self.n_cols..].to_vec();
        let (u, v) = self.eval_with_intermediate_values(x, y).last().unwrap().clone();
        [u, v].concat()
    }

    pub fn jive(&self, b: usize, input: Vec<FieldElement>) -> Vec<FieldElement> {
        if b < 2 {
            panic!("b must be at least 2");
        }
        let input_size = self.input_size();
        if input_size % b != 0 {
            panic!("b must divide the input size");
        }
        let c = input_size / b;

        let u = self.call(input.clone());
        let mut compressed = vec![];
        for i in 0..c {
            let mut acc = self.field.zero();
            for j in 0..b {
                acc = &acc + &input[i + c * j] + &u[i + c * j];
            }
            compressed.push(acc);
        }
        compressed
    }
}
