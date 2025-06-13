use modulus::modulus::FieldElement;
use rescueprime::rescueprime::RescuePrime as RescuePrime;
use num_bigint::BigInt;
use num_integer::Integer;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use mylib::AU;
use blake3;

fn main() {
    println!("{:?}", blake3::Hash("abcde"));
    let test = BigInt::from(340282366920938463463374557953744961537u128);
    let test2 = BigInt::from(0);
    println!("{:?}", test.gcd(&test2));
    let rescue = RescuePrime::new();
    let field = modulus::modulus::Field{ p: 340282366920938463463374557953744961537 };
    let teststring: Vec<FieldElement> = vec![
        FieldElement{value: 21493836, field},
        FieldElement{value: 340282366920938463463374557953736934518, field},
        FieldElement{value: 914760, field},
        FieldElement{value: 340282366920938463463374557953744928504, field},
        FieldElement{value: 364, field}
    ];
    println!("Hash:{:?}", rescue.hash(teststring));
}
