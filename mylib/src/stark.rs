use crate::modulus;
use modulus::{Field, FieldElement};
use crate::fri;
use fri::Fri;
use crate::polynomial;
use polynomial::Polynomial;

struct Stark {
    field: Field,
    expansion_factor: usize,
    num_colinearity_checks: usize,
    security_level: usize,
    num_registers: u128,
    num_cycles: u128,
    transision_constraints_degree: u128,
    original_trace_length: u128,
    num_randomizers: usize,
    generator: u128,
    omega: u128,
    omicron: u128,
    fri: Fri,
    omicron_domain: Vec<FieldElement>,
}

impl Stark {
    fn new(field: Field, expansion_factor: usize, num_colinearity_checks: usize, security_level: usize, num_registers: u128, num_cycles: u128, transition_constraints_degree: usize) -> Self {
        assert!((field.p.count_ones() as usize) >= security_level, "p must have at least as many bits as security level");
        assert!((expansion_factor & (expansion_factor - 1)) == 0, "expansion factor must be a power of 2");
        assert!(expansion_factor >= 4, "expansion factor must be 4 or greater");
        assert!(num_colinearity_checks * 2 >= security_level, "number of colinearity checks must be at least half of security level");

        let num_randomizers= 4 * num_colinearity_checks;
        let original_trace_length = num_cycles;

        let randomized_trace_length = original_trace_length + num_randomizers as u128;
        let omicron_domain_length:u128 = 1 << (randomized_trace_length * transition_constraints_degree as u128).next_power_of_two().trailing_zeros();
        let fri_domain_length:u128 = omicron_domain_length * expansion_factor as u128;

        let generator = field.generator();
        let omega = field.primitive_nth_root(fri_domain_length);
        let omicron = field.primitive_nth_root(omicron_domain_length);

        let mut omicron_domain = Vec::new();
        for i in 0..omicron_domain_length {
            omicron_domain.push(omicron.pow(i as u128));
        }

        let fri = Fri::new(generator, omega, fri_domain_length, expansion_factor, num_colinearity_checks);

        Stark {
            field,
            expansion_factor,
            num_colinearity_checks,
            security_level,
            num_registers,
            original_trace_length,
            fri,
            omicron_domain,
        }
    }

    pub fn transition_degree_bounds(&self, transition_constraints: Vec<u128>){
        let mut point_degrees = vec![1];
        point_degrees.extend(vec![self.original_trace_length + self.num_randomizers - 1; 2 * self.num_registers]);

        transition_constraints.iter().map(|a| {
            a.dictionary.iter().map(|(k, _v)| {
                k.iter().zip(point_degrees.iter()).map(|(r, l)| r * l).sum::<usize>()
            }).max().unwrap()
        }).collect()
    }
    pub fn transition_quoient_degree_bounds(&self, transition_constraints: Vec<u128>){
        self.transition_degree_bounds(transition_constraints)
            .into_iter()
            .map(|d| d - (self.original_trace_length - 1))
            .collect()
    }
    pub fn max_degree(&self, transition_constraints: Vec<u128>) -> usize {
        let max_degree = *self.transition_quotient_degree_bounds(transition_constraints).iter().max().unwrap();
        (1 << (max_degree.next_power_of_two().trailing_zeros())) - 1
    }
    pub fn transition_zerofier(&self) -> Polynomial {
        let domain = &self.omicron_domain[..self.original_trace_length - 1];
        Polynomial::zerofier_domain(domain)
    }
    pub fn boundary_zerofiers(&self, boundary: &[(u128, usize, u128)]) -> Vec<Polynomial> {
        let mut zerofiers = Vec::new();

        for s in 0..self.num_registers {
            let points: Vec<u128> = boundary
                .iter()
                .filter_map(|&(c, r, _v)| if r == s { Some(self.omicron.pow(c as u32)) } else { None })
                .collect();

            zerofiers.push(Polynomial::zerofier_domain(&points));
        }

        zerofiers
    }
    pub fn boundary_interpolants(&self, boundary: &[(u128, usize, u128)]) -> Vec<Polynomial> {
        let mut interpolants = Vec::new();

        for s in 0..self.num_registers {
            let points: Vec<(u128, u128)> = boundary
                .iter()
                .filter_map(|&(c, r, v)| if r == s { Some((c, v)) } else { None })
                .collect();

            let domain: Vec<u128> = points
                .iter()
                .map(|&(c, _v)| self.omicron.pow(c as u32))
                .collect();

            let values: Vec<u128> = points.iter().map(|&(_c, v)| v).collect();

            interpolants.push(Polynomial::interpolate_domain(&domain, &values));
        }

        interpolants
    }
    pub fn boundary_quotient_degree_bounds(
        &self,
        randomized_trace_length: usize,
        boundary: &[(u128, usize, u128)],
    ) -> Vec<usize> {
        let randomized_trace_degree = randomized_trace_length - 1;
        self.boundary_zerofiers(boundary)
            .iter()
            .map(|bz| randomized_trace_degree - bz.degree())
            .collect()
    }
}