use hpke_rs_crypto::{error::Error, types::KemAlgorithm, HpkeCrypto};
use hpke_rs_libcrux::HpkeLibcrux;

// The vectors come from libcrux-kem/tests/xwing.rs at the HPKE 0.7 release.
// They use draft-connolly-cfrg-xwing-kem-06, section 7.
#[test]
fn xwing_known_answers() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("xwing-draft06.json")).unwrap();
    for vector in vectors.as_array().unwrap() {
        let bytes = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let (pk, sk) =
            HpkeLibcrux::kem_key_gen_derand(KemAlgorithm::XWingDraft06, &bytes("seed")).unwrap();
        assert_eq!(pk, bytes("pk"));
        assert_eq!(sk, bytes("sk"));
        let ss = HpkeLibcrux::kem_decaps(KemAlgorithm::XWingDraft06, &bytes("ct"), &sk).unwrap();
        assert_eq!(ss, bytes("ss"));
    }
}

#[test]
fn xwing_invalid_key_lengths_return_errors() {
    let alg = KemAlgorithm::XWingDraft06;
    let mut rng = HpkeLibcrux::prng();
    let (pk, sk) = HpkeLibcrux::kem_key_gen(alg, &mut rng).unwrap();
    let (ss, ct) = HpkeLibcrux::kem_encaps(alg, &pk, &mut rng).unwrap();
    assert_eq!(HpkeLibcrux::kem_decaps(alg, &ct, &sk).unwrap(), ss);

    for len in 0..pk.len() {
        assert!(matches!(
            HpkeLibcrux::kem_encaps(alg, &pk[..len], &mut rng),
            Err(Error::KemInvalidPublicKey)
        ));
    }
    let mut long_pk = pk.clone();
    long_pk.push(0);
    assert!(matches!(
        HpkeLibcrux::kem_encaps(alg, &long_pk, &mut rng),
        Err(Error::KemInvalidPublicKey)
    ));
    for len in 0..sk.len() {
        assert!(matches!(
            HpkeLibcrux::kem_decaps(alg, &ct, &sk[..len]),
            Err(Error::KemInvalidSecretKey)
        ));
    }
    let mut long_sk = sk.clone();
    long_sk.push(0);
    assert!(matches!(
        HpkeLibcrux::kem_decaps(alg, &ct, &long_sk),
        Err(Error::KemInvalidSecretKey)
    ));
    for len in [0, 1, ct.len() - 1] {
        assert!(matches!(
            HpkeLibcrux::kem_decaps(alg, &ct[..len], &sk),
            Err(Error::AeadInvalidCiphertext)
        ));
    }
}
