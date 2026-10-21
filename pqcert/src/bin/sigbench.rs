use pqcert::sig::Scheme; use std::time::Instant;
fn main() {
    for s in [Scheme::D2, Scheme::D3, Scheme::D5, Scheme::F512] {
        let (pk, sk) = s.keygen(&[3u8; 32]); let msg = [9u8; 32];
        let mut ts = vec![]; let mut tv = vec![]; let mut sig = vec![];
        for _ in 0..201 { let t = Instant::now(); sig = s.sign(&sk, &msg); ts.push(t.elapsed().as_secs_f64()); }
        for _ in 0..201 { let t = Instant::now(); assert!(s.verify(&pk, &msg, &sig)); tv.push(t.elapsed().as_secs_f64()); }
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap()); tv.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("{{\"scheme\":\"{}\",\"pk\":{},\"sig\":{},\"sign_ms\":{:.4},\"verify_ms\":{:.4}}}", s.name(), s.pk_len(), sig.len(), ts[100]*1e3, tv[100]*1e3);
    }
}
