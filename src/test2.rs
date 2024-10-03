fn main() {
    pub fn xgcd(a: u128, b: u128) -> (u128, u128, u128) {
        let (mut old_r, mut r): (u128, u128) = (a, b);
        let (mut old_s, mut s): (u128, u128) = (1, 0);
        let (mut old_t, mut t): (u128, u128) = (0, 1);

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
    let test = xgcd(15, 340282366920938463463374557953744961537u128);
    println!("{:?}", test);
}