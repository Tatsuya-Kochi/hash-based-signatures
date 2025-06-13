use rand::Rng;  // Rngトレイトをインポート
pub mod modulus; // フィールド演算モジュール
pub mod polynomial; // 多項式演算モジュール
pub mod rescue_prime; // RescuePrimeモジュール
pub mod lamport_plus; // Lamport+モジュール
pub mod merkle; // マークルツリーモジュール
pub mod fri;    // FRIモジュール
pub mod stark;  // STARKモジュール
pub mod agg_sig; // 集約署名モジュール
pub mod threshold_sig; // 閾値署名モジュール
pub mod proofstream; 


pub fn test() -> u128 {
    // スレッドローカルな乱数生成器を取得
    let mut rng = rand::thread_rng();

    // 0から9の範囲の整数を生成
    let random_number: u32 = rng.gen_range(0..10);
    println!("生成されたランダムな整数: {}", random_number);

    // 128ビットの乱数を生成
    let random_bytes: [u8; 16] = rng.gen();  // 16バイト = 128ビット
    println!("生成された128ビットの乱数: {:?}", random_bytes);
    let bits: u128 = u128::from_be_bytes(random_bytes);
    bits
}
// バイト配列をu128に変換する関数
fn bytes_to_u128(bytes: &[u8; 16]) -> u128 {
    u128::from_be_bytes(*bytes) // ビッグエンディアンとして変換
}
