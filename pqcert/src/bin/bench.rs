use pqcert::*; use pqcert::sig::Scheme;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rayon::prelude::*;
use std::time::Instant;

fn weights(n: usize, dist: &str, rng: &mut StdRng) -> Vec<u64> {
    let raw: Vec<f64> = match dist {
        "zipf" => (1..=n).map(|i| 1.0 / (i as f64)).collect(),
        "lognormal" => (0..n).map(|_| { let u1: f64 = rng.gen::<f64>().max(1e-12); let u2: f64 = rng.gen(); let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos(); (1.5 * z).exp() }).collect(),
        _ => vec![1.0; n],
    };
    let s: f64 = raw.iter().sum();
    raw.iter().map(|x| ((x / s) * 1e12).round().max(1.0) as u64).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let scheme = Scheme::parse(&a[1]); let n: usize = a[2].parse().unwrap();
    let signed_frac: f64 = a[3].parse().unwrap(); let dist = a[4].as_str();
    // "1/3" => integer floor(W/3) (exact BFT threshold); otherwise a float fraction of W
    let proven_exact_third = a[5] == "1/3";
    let proven_frac: f64 = if proven_exact_third { 1.0 / 3.0 } else { a[5].parse().unwrap() };
    let model = if a[6] == "qrom" { Model::Qrom } else { Model::Classical };
    let reps: usize = a[7].parse().unwrap();
    let lambda = 128.0; let log2q = 64.0;
    let mut rng = StdRng::seed_from_u64(42);
    let w = weights(n, dist, &mut rng);
    let total: u64 = w.iter().sum();
    let t0 = Instant::now();
    let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n).into_par_iter().map(|i| { let mut s = [0u8; 32]; s[..8].copy_from_slice(&(i as u64).to_le_bytes()); scheme.keygen(&s) }).collect();
    let t_kg = t0.elapsed().as_secs_f64();
    let pks: Vec<Vec<u8>> = keys.iter().map(|k| k.0.clone()).collect();
    let att = Merkle::from_leaf_data(&(0..n).map(|i| att_leaf(&pks[i], w[i])).collect::<Vec<_>>());
    let msg = keccak(&[b"sidechain-header-epoch-17"]).to_vec();
    // random signer subset reaching signed_frac of total weight (random order)
    let mut order: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() { let j = rng.gen_range(0..=i); order.swap(i, j); }
    let mut signer = vec![false; n]; let mut acc = 0u64;
    for &i in &order { if (acc as f64) >= signed_frac * total as f64 { break; } signer[i] = true; acc += w[i]; }
    let t1 = Instant::now();
    let sigs: Vec<Option<Vec<u8>>> = (0..n).into_par_iter().map(|i| if signer[i] { Some(scheme.sign(&keys[i].1, &msg)) } else { None }).collect();
    let t_sign_total = t1.elapsed().as_secs_f64();
    let nsign = signer.iter().filter(|x| **x).count();
    // single-thread per-signature cost
    let t2 = Instant::now(); let m = 50.min(n); for i in 0..m { let _ = scheme.sign(&keys[i].1, &msg); } let t_sign1 = t2.elapsed().as_secs_f64() / m as f64;
    let proven = if proven_exact_third { total / 3 } else { (proven_frac * total as f64) as u64 };
    let p = Params { msg: &msg, proven, lambda, log2q, model, total, n, min_ratio: 1.1 };
    let mut tb = vec![]; let mut tv = vec![]; let mut cert = None;
    for _ in 0..reps {
        let t = Instant::now(); let c = build(&p, &pks, &w, &sigs, &att).unwrap(); tb.push(t.elapsed().as_secs_f64());
        let t = Instant::now(); verify(&p, scheme, &att.root(), &c).unwrap(); tv.push(t.elapsed().as_secs_f64());
        cert = Some(c);
    }
    tb.sort_by(|a, b| a.partial_cmp(b).unwrap()); tv.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let c = cert.unwrap();
    // negative tests: tamper one signature / one interval / drop a reveal
    let mut bad = c.clone(); bad.reveals[0].sig[10] ^= 1; let neg1 = verify(&p, scheme, &att.root(), &bad).is_err();
    let mut bad = c.clone(); bad.reveals[0].l += 1; let neg2 = verify(&p, scheme, &att.root(), &bad).is_err();
    let mut bad = c.clone(); if bad.reveals.len() > 1 { bad.reveals.pop(); } let neg3 = verify(&p, scheme, &att.root(), &bad).is_err() || c.reveals.len() == 1;
    let mut bad = c.clone(); bad.signed = total + 1; let neg4 = verify(&p, scheme, &att.root(), &bad).is_err();
    // extra valid but unused reveal (|P| must equal the set of positions hit by coins)
    let neg5 = match with_extra_reveal(&c, &pks, &w, &sigs, &att) { Some(bad) => verify(&p, scheme, &att.root(), &bad).is_err(), None => true };
    println!("{}", serde_json::json!({
        "scheme": scheme.name(), "n": n, "dist": dist, "signed_frac_target": signed_frac, "n_signers": nsign,
        "signed_weight_frac": c.signed as f64 / total as f64, "proven_arg": a[5], "proven_frac": proven as f64 / total as f64, "proven": proven, "total": total, "model": a[6],
        "k": c.k, "distinct_reveals": c.reveals.len(), "proof_sig_hashes": c.proof_sig.len(), "proof_att_hashes": c.proof_att.len(),
        "cert_bytes": c.size_bytes(), "naive_bytes": nsign * (scheme.pk_len() + scheme.sig_len() + 8),
        "keygen_total_s": t_kg, "sign_one_ms": t_sign1 * 1e3, "sign_all_parallel_s": t_sign_total,
        "build_ms_median": tb[reps / 2] * 1e3, "verify_ms_median": tv[reps / 2] * 1e3,
        "neg_tamper_sig": neg1, "neg_tamper_interval": neg2, "neg_drop_reveal": neg3, "neg_signed_gt_total": neg4, "neg_extra_unused_reveal": neg5
    }));
}
