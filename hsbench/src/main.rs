use hashsig::signature::SignatureScheme;
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_18::SIGTopLevelTargetSumLifetime18Dim64Base8 as L18;
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8 as L32H;
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::tradeoff::SIGTopLevelTargetSumLifetime32Dim48Base10 as L32T;
use hashsig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::size_optimized::SIGTopLevelTargetSumLifetime32Dim32Base26 as L32S;
use std::time::Instant;

fn run<T: SignatureScheme>(name: &str, active: usize) {
    let mut rng = rand::rng();
    let t = Instant::now();
    let (pk, sk) = T::key_gen(&mut rng, 0, active);
    let kg = t.elapsed().as_secs_f64();
    let msg = [7u8; hashsig::MESSAGE_LENGTH];
    let cfg = bincode::config::standard().with_fixed_int_encoding();
    let mut ts = vec![]; let mut tv = vec![]; let mut sz = 0; let mut pksz = 0;
    for e in 0..20u32 {
        let t = Instant::now(); let sig = T::sign(&sk, e, &msg).unwrap(); ts.push(t.elapsed().as_secs_f64());
        let t = Instant::now(); assert!(T::verify(&pk, e, &msg, &sig)); tv.push(t.elapsed().as_secs_f64());
        sz = bincode::serde::encode_to_vec(&sig, cfg).unwrap().len();
        pksz = bincode::serde::encode_to_vec(&pk, cfg).unwrap().len();
    }
    ts.sort_by(|a,b| a.partial_cmp(b).unwrap()); tv.sort_by(|a,b| a.partial_cmp(b).unwrap());
    println!("{}", serde_json::json!({"scheme": name, "active_epochs": active, "keygen_s": kg, "sig_bytes": sz, "pk_bytes": pksz,
        "sign_ms": ts[10]*1e3, "verify_ms": tv[10]*1e3}));
}
fn main() {
    let which = std::env::args().nth(1).unwrap_or("l18".into());
    match which.as_str() {
        "l18" => run::<L18>("XMSS-TS L2^18 dim64 base8", 1 << 10),
        "l32h" => run::<L32H>("XMSS-TS L2^32 dim64 base8 (hashing-opt)", 1 << 17),
        "l32t" => run::<L32T>("XMSS-TS L2^32 dim48 base10 (tradeoff)", 1 << 17),
        "l32s" => run::<L32S>("XMSS-TS L2^32 dim32 base26 (size-opt)", 1 << 17),
        _ => {}
    }
}
