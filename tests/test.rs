use mylib;

#[test]
    fn it_works() {
        for i in 0..256 {
        let result = mylib::test();
        assert!(result <= u128::MAX, "Number is not 128 bits long.");
        println!("{:?}", result);
        }
    }
#[test]
    fn tttest() {
        let counter: u128 = 0; //カウンタC
        let rng = rand::SystemRandom::new();
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)?;

        let msg = "hello, world";

        let tag = hmac::sign(&key, msg.as_bytes());
        println!("{:?}", tag);
    }
