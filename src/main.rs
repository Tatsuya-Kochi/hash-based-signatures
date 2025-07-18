fn main() {
    let number: u128 = 340282366920938463463374607431768211156;
    
    let binary_string = format!("{:b}", number);
    let index = 127;
    if let Some(character) = binary_string.chars().nth(index) {
        println!("Character at index {}: {}", index, character);
    } else {
        println!("Index out of bounds.");
    }
    // 結果を表示
    println!("The binary representation of {} is {}", number, binary_string);

    let binary_string = String::from("1111"); // 13 in decimal

    // 基数2（ビット）の文字列を10進数に変換
    let decimal_number = u64::from_str_radix(&binary_string, 2).expect("Failed to convert");

    println!("Decimal number: {}", decimal_number); // 出力: Decimal number: 13
}