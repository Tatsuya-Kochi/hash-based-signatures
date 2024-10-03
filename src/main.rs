mod modulus;
mod rescueprime;
use modulus::modulus::FieldElement;
use rescueprime::rescueprime::RescuePrime as RescuePrime;
use num_bigint::BigInt;
use num_integer::Integer;
use sha2::Sha256;
use hmac::{Hmac, Mac};
fn main() {
    fn reduce_message(input: &[u8]) -> () {
        type HmacSha256 = Hmac<Sha256>;

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
        .expect("HMAC can take key of any size");
    mac.update(b"input message");

    // `result` has type `Output` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    // To get underlying array use `into_bytes` method, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `Output`
    let code_bytes = result.into_bytes();
    let a = code_bytes[0] + 1;
    println!("HMAC:{}", code_bytes[0]);
    }
    
    let input = b"input message";  
    println!("b:{:?}", input);
    let test_reduce = reduce_message(input);

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
