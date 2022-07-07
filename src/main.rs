#![allow(dead_code)]
use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::{EncryptWithChosenRandomness, Keypair, Paillier, Randomness, RawPlaintext,Encrypt,Decrypt ,Add};

use rayon::range;
// use zk_paillier::zkproofs::RangeProofTrait;
use zk_paillier::zkproofs::RangeProofNi;
use zk_paillier::zkproofs::*;


const STATISTICAL_ERROR_FACTOR: usize = 40;

const RANGE_BITS: usize = 256; //for elliptic curves with 256bits for example

fn test_keypair() -> Keypair {
    let p = BigInt::from_str_radix("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517", 10).unwrap();
    let q = BigInt::from_str_radix("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463", 10).unwrap();
    Keypair { p, q }
}


fn test(hex_str1:String,hex_str2:String){
    let (ek, dk) = test_keypair().keys();
    let num1 = BigInt::from_hex(&hex_str1).unwrap();
    let num2 = BigInt::from_hex(&hex_str2).unwrap();
    println!("开始加密num1:{}",num1);
    let start = std::time::Instant::now();
    let c1 = Paillier::encrypt(&ek,RawPlaintext::from(num1));
    let elapsed = start.elapsed().as_secs();
    println!("加密完成用时:{}秒\n",elapsed);

    println!("开始加密num2:{}",num2);
    let start = std::time::Instant::now();
    let c2 = Paillier::encrypt(&ek,RawPlaintext::from(num2));
    let elapsed = start.elapsed().as_secs();
    println!("加密完成用时:{}秒\n",elapsed);

    println!("开始计算num3=num1+num2:");
    let start = std::time::Instant::now();
    let c = Paillier::add(&ek, c1, c2);
    let elapsed = start.elapsed().as_secs();
    println!("计算完成用时:{}秒\n",elapsed);

    println!("开始解密num3:{:?}",c);
    let start = std::time::Instant::now();
    let num3: BigInt = Paillier::decrypt(&dk, &c).into();
    let elapsed = start.elapsed().as_secs();
    println!("解密完成,num3={},用时:{}秒\n",num3,elapsed);

    let m: BigInt = Paillier::decrypt(&dk, c).into();
    println!("证明m值:{},位于区间[0,3(m+1)]内:",&m);
    let secret_r = BigInt::sample_below(&ek.n);
    let cipher_x = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(&m),
        &Randomness(secret_r.clone()),
    );
    let start = std::time::Instant::now();
    let range = (&m+1)*5;
    let range_proof = RangeProofNi::prove(&ek, &range, &cipher_x.0, &m, &secret_r);
    let proof_json = serde_json::to_string(&range_proof).unwrap();
    let elapsed = start.elapsed().as_secs();
    println!("证明生成,大小为:{}kb,用时{}秒\n",proof_json.len()/1000,elapsed);

    println!("验证证明:");
    let start = std::time::Instant::now();
    range_proof
        .verify(&ek, &cipher_x.0)
        .expect("range proof error");    
    let elapsed = start.elapsed().as_secs();
    println!("证明验证通过，用时{}秒",elapsed);


}




fn test_range_proof_correct_proof() {
    // common:
    let range = BigInt::sample(RANGE_BITS);
    // prover:
    let (ek, _dk) = test_keypair().keys();
    let (verifier_ek, verifier_dk) = test_keypair().keys();
    // verifier:
    let (com, r, e) = RangeProof::verifier_commit(&verifier_ek);
    let (challenge, verification_aid) = CorrectKey::challenge(&verifier_ek);
    let proof_results = CorrectKey::prove(&verifier_dk, &challenge);
    let _result = CorrectKey::verify(&proof_results.unwrap(), &verification_aid);
    assert!(RangeProof::verify_commit(&verifier_ek, &com, &r, &e).is_ok());
    // prover:
    let (encrypted_pairs, data_and_randmoness_pairs) =
        RangeProof::generate_encrypted_pairs(&ek, &range, STATISTICAL_ERROR_FACTOR);
    // prover:
    let secret_r = BigInt::sample_below(&ek.n);
    let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
    // common:
    let cipher_x = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(&secret_x),
        &Randomness(secret_r.clone()),
    );
    // verifer decommits (tested in test_commit_decommit)
    // prover:
    let z_vector = RangeProof::generate_proof(
        &ek,
        &secret_x,
        &secret_r,
        &e,
        &range,
        &data_and_randmoness_pairs,
        STATISTICAL_ERROR_FACTOR,
    );
    // verifier:
    let result = RangeProof::verifier_output(
        &ek,
        &e,
        &encrypted_pairs,
        &z_vector,
        &range,
        &cipher_x.0,
        STATISTICAL_ERROR_FACTOR,
    );
    assert!(result.is_ok());
}








fn main() {
    test("10".to_string(), "10".to_string());
    test("10000000000000000000000000000000000000000000000000000000000000000".to_string(), "10000000000000000000000000000000000000000000000000000000000000000".to_string());
    test("1000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(), "1000000000000000000000000000000000000000000000000000000000000000000000000000".to_string());
    test_range_proof_correct_proof();
}