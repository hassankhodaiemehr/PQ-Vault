//! pqcert: corrected, QROM-parameterised compact certificates of collective
//! knowledge (Micali et al., S&P'21) instantiated with Dilithium/ML-DSA.
//! Revision artefact for the TDSC submission.
use sha3::Digest;
#[cfg(not(feature = "h384"))] use sha3::Keccak256 as HashFn;
#[cfg(feature = "h384")] use sha3::Keccak384 as HashFn;
#[cfg(not(feature = "h384"))] pub const HLEN: usize = 32;
#[cfg(feature = "h384")] pub const HLEN: usize = 48;

pub mod sig {
    use crystals_dilithium::{dilithium2, dilithium3, dilithium5};
    use pqcrypto_falcon::falconpadded512 as fal;
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
    #[derive(Clone, Copy, Debug, PartialEq)]
    /// D2/D3/D5: CRYSTALS-Dilithium round 3 (`crystals-dilithium` crate).
    /// M44: FIPS 204 ML-DSA-44 (RustCrypto `ml-dsa` crate, pinned =0.1.1): pure ML-DSA, empty context,
    /// deterministic signing variant (rnd = 0^32); keygen = ML-DSA.KeyGen_internal from the 32-byte seed.
    pub enum Scheme { D2, D3, D5, F512, M44 }
    impl Scheme {
        pub fn parse(s: &str) -> Scheme { match s { "D3" => Scheme::D3, "D5" => Scheme::D5, "F512" => Scheme::F512, "M44" => Scheme::M44, _ => Scheme::D2 } }
        pub fn name(&self) -> &'static str { match self { Scheme::D2 => "Dilithium2-r3", Scheme::D3 => "Dilithium3-r3", Scheme::D5 => "Dilithium5-r3", Scheme::F512 => "Falcon-512", Scheme::M44 => "ML-DSA-44 (FIPS 204)" } }
        pub fn pk_len(&self) -> usize { match self { Scheme::D2 => dilithium2::PUBLICKEYBYTES, Scheme::D3 => dilithium3::PUBLICKEYBYTES, Scheme::D5 => dilithium5::PUBLICKEYBYTES, Scheme::F512 => fal::public_key_bytes(), Scheme::M44 => 1312 } }
        pub fn sig_len(&self) -> usize { match self { Scheme::D2 => dilithium2::SIGNBYTES, Scheme::D3 => dilithium3::SIGNBYTES, Scheme::D5 => dilithium5::SIGNBYTES, Scheme::F512 => fal::signature_bytes(), Scheme::M44 => 2420 } }
        /// returns (pk, sk_bytes); for M44 sk_bytes is the 32-byte FIPS 204 seed xi
        pub fn keygen(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
            match self {
                Scheme::D2 => { let k = dilithium2::Keypair::generate(Some(seed)); (k.public.to_bytes().to_vec(), k.to_bytes().to_vec()) }
                Scheme::D3 => { let k = dilithium3::Keypair::generate(Some(seed)); (k.public.to_bytes().to_vec(), k.to_bytes().to_vec()) }
                Scheme::D5 => { let k = dilithium5::Keypair::generate(Some(seed)); (k.public.to_bytes().to_vec(), k.to_bytes().to_vec()) }
                Scheme::F512 => { let _ = seed; let (pk, sk) = fal::keypair(); (pk.as_bytes().to_vec(), sk.as_bytes().to_vec()) }
                Scheme::M44 => {
                    let mut xi = [0u8; 32]; xi.copy_from_slice(&seed[..32]);
                    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&xi.into());
                    (ml_dsa::Keypair::verifying_key(&sk).encode().to_vec(), xi.to_vec())
                }
            }
        }
        pub fn sign(&self, kp: &[u8], msg: &[u8]) -> Vec<u8> {
            match self {
                Scheme::D2 => dilithium2::Keypair::from_bytes(kp).sign(msg).to_vec(),
                Scheme::D3 => dilithium3::Keypair::from_bytes(kp).sign(msg).to_vec(),
                Scheme::D5 => dilithium5::Keypair::from_bytes(kp).sign(msg).to_vec(),
                Scheme::F512 => fal::detached_sign(msg, &fal::SecretKey::from_bytes(kp).unwrap()).as_bytes().to_vec(),
                Scheme::M44 => {
                    let mut xi = [0u8; 32]; xi.copy_from_slice(&kp[..32]);
                    let esk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::from_seed(&xi.into());
                    esk.sign_deterministic(msg, &[]).expect("ctx <= 255").encode().to_vec()
                }
            }
        }
        pub fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            if pk.len() != self.pk_len() || sig.len() != self.sig_len() { return false; }
            match self {
                Scheme::D2 => dilithium2::PublicKey::from_bytes(pk).verify(msg, sig),
                Scheme::D3 => dilithium3::PublicKey::from_bytes(pk).verify(msg, sig),
                Scheme::D5 => dilithium5::PublicKey::from_bytes(pk).verify(msg, sig),
                Scheme::F512 => fal::verify_detached_signature(&fal::DetachedSignature::from_bytes(sig).unwrap(), msg, &fal::PublicKey::from_bytes(pk).unwrap()).is_ok(),
                Scheme::M44 => {
                    let Ok(enc) = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(pk) else { return false };
                    let Ok(s) = ml_dsa::Signature::<ml_dsa::MlDsa44>::try_from(sig) else { return false };
                    ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&enc).verify_with_context(msg, &[], &s)
                }
            }
        }
    }
}

pub type H = [u8; HLEN];
pub fn keccak(parts: &[&[u8]]) -> H { let mut h = HashFn::new(); for p in parts { h.update(p); } h.finalize().into() }
const LEAF: &[u8] = &[0x00];
const NODE: &[u8] = &[0x01];

/// Domain-separated binary Merkle tree (leaf/node prefixes), padded to 2^d.
pub struct Merkle { pub levels: Vec<Vec<H>>, pub n: usize }
impl Merkle {
    pub fn from_leaf_data(data: &[Vec<u8>]) -> Merkle {
        let n = data.len();
        let mut size = 1; while size < n { size <<= 1; }
        let mut lvl: Vec<H> = (0..size).map(|i| if i < n { keccak(&[LEAF, &data[i]]) } else { keccak(&[LEAF, b"pad"]) }).collect();
        let mut levels = vec![lvl.clone()];
        while lvl.len() > 1 {
            lvl = lvl.chunks(2).map(|c| keccak(&[NODE, &c[0], &c[1]])).collect();
            levels.push(lvl.clone());
        }
        Merkle { levels, n }
    }
    pub fn root(&self) -> H { self.levels.last().unwrap()[0] }
    pub fn depth(&self) -> usize { self.levels.len() - 1 }
    /// Compact multiproof: sibling hashes not derivable from the opened set, level by level (sorted).
    pub fn multiproof(&self, pos: &[usize]) -> Vec<H> {
        let mut known: Vec<usize> = pos.to_vec(); known.sort(); known.dedup();
        let mut out = vec![];
        for l in 0..self.depth() {
            let set: std::collections::BTreeSet<usize> = known.iter().cloned().collect();
            for &i in &known { let s = i ^ 1; if !set.contains(&s) { out.push(self.levels[l][s]); } }
            let mut nk: Vec<usize> = known.iter().map(|i| i >> 1).collect(); nk.dedup(); known = nk;
        }
        out
    }
    pub fn verify_multiproof(root: &H, depth: usize, pos: &[usize], leaves: &[H], proof: &[H]) -> bool {
        // pos sorted & distinct, leaves aligned
        let mut cur: Vec<(usize, H)> = pos.iter().cloned().zip(leaves.iter().cloned()).collect();
        let mut pi = 0usize;
        for _ in 0..depth {
            let mut next: Vec<(usize, H)> = vec![]; let mut k = 0;
            while k < cur.len() {
                let (i, h) = cur[k];
                let (l, r);
                if i & 1 == 0 && k + 1 < cur.len() && cur[k + 1].0 == i + 1 { l = h; r = cur[k + 1].1; k += 2; }
                else { if pi >= proof.len() { return false; } let s = proof[pi]; pi += 1; if i & 1 == 0 { l = h; r = s } else { l = s; r = h } k += 1; }
                next.push((i >> 1, keccak(&[NODE, &l, &r])));
            }
            cur = next;
        }
        pi == proof.len() && cur.len() == 1 && cur[0].1 == *root
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Model { Classical, Qrom }

/// Number of reveals. Classical: Micali et al. (lambda + log2 q)/log2(Ws/Wp).
/// QROM (this work, Thm. 6): (lambda + 2 log2 q + kappa_Q)/log2(Ws/Wp), kappa_Q = 4 >= log2(12) (explicit CMS lifting constant).
pub fn num_reveals(lambda: f64, log2q: f64, signed: u64, proven: u64, model: Model) -> usize {
    assert!(signed > proven);
    let ratio = (signed as f64 / proven as f64).log2();
    let num = match model { Model::Classical => lambda + log2q, Model::Qrom => lambda + 2.0 * log2q + 4.0 };
    (num / ratio).ceil() as usize
}

pub fn coin(j: u64, r_sig: &H, r_att: &H, signed: u64, proven: u64, msg: &[u8], n: u64) -> u64 {
    let h = keccak(&[b"CCOK-COIN-v2", &j.to_le_bytes(), r_sig, r_att, &signed.to_le_bytes(), &proven.to_le_bytes(), &n.to_le_bytes(), msg]);
    let mut b = [0u8; 16]; b.copy_from_slice(&h[..16]);
    // 128-bit reduction: statistical distance <= signed/2^128 per coin
    (u128::from_le_bytes(b) % signed as u128) as u64
}

pub fn att_leaf(pk: &[u8], w: u64) -> Vec<u8> { let mut v = pk.to_vec(); v.extend_from_slice(&w.to_le_bytes()); v }
pub fn sig_leaf(sig: Option<&[u8]>, l: u64) -> Vec<u8> {
    match sig { Some(s) => { let mut v = vec![1u8]; v.extend_from_slice(s); v.extend_from_slice(&l.to_le_bytes()); v }, None => b"\x00unsigned".to_vec() }
}

#[derive(Clone, Debug)]
pub struct Reveal { pub pos: usize, pub pk: Vec<u8>, pub weight: u64, pub sig: Vec<u8>, pub l: u64 }

#[derive(Clone, Debug)]
pub struct Certificate {
    pub r_sig: H, pub signed: u64, pub n: usize, pub k: usize,
    pub reveals: Vec<Reveal>, pub proof_sig: Vec<H>, pub proof_att: Vec<H>,
}
impl Certificate {
    pub fn size_bytes(&self) -> usize {
        HLEN + 8 + 4 + self.reveals.iter().map(|r| 4 + r.pk.len() + 8 + r.sig.len() + 8).sum::<usize>() + HLEN * (self.proof_sig.len() + self.proof_att.len())
    }
}

/// `total` = total committed stake W and `n` = number of attestors, both taken from verifier state (not from the prover);
/// `min_ratio` = 1+delta, the minimum accepted Ws/Wp (bounds k_rev).
pub struct Params<'a> { pub msg: &'a [u8], pub proven: u64, pub lambda: f64, pub log2q: f64, pub model: Model, pub total: u64, pub n: usize, pub min_ratio: f64 }

pub fn build(p: &Params, pks: &[Vec<u8>], weights: &[u64], sigs: &[Option<Vec<u8>>], att: &Merkle) -> Result<Certificate, String> {
    let n = pks.len();
    // L-values accumulated over signed slots only (index order)
    let mut ls = vec![0u64; n]; let mut acc = 0u64;
    for i in 0..n { if sigs[i].is_some() { ls[i] = acc; acc += weights[i]; } }
    let signed = acc;
    if signed <= p.proven { return Err(format!("insufficient signed weight {} <= {}", signed, p.proven)); }
    let leaves: Vec<Vec<u8>> = (0..n).map(|i| sig_leaf(sigs[i].as_deref(), ls[i])).collect();
    let st = Merkle::from_leaf_data(&leaves);
    let r_sig = st.root(); let r_att = att.root();
    let k = num_reveals(p.lambda, p.log2q, signed, p.proven, p.model);
    // signed index list for binary search
    let signed_idx: Vec<usize> = (0..n).filter(|&i| sigs[i].is_some()).collect();
    let mut chosen = std::collections::BTreeSet::new();
    for j in 0..k as u64 {
        let c = coin(j, &r_sig, &r_att, signed, p.proven, p.msg, n as u64);
        // find i with L_i <= c < L_i + w_i
        let pos = signed_idx.partition_point(|&i| ls[i] + weights[i] <= c);
        chosen.insert(signed_idx[pos]);
    }
    let pos: Vec<usize> = chosen.into_iter().collect();
    let reveals = pos.iter().map(|&i| Reveal { pos: i, pk: pks[i].clone(), weight: weights[i], sig: sigs[i].clone().unwrap(), l: ls[i] }).collect();
    Ok(Certificate { r_sig, signed, n, k, proof_sig: st.multiproof(&pos), proof_att: att.multiproof(&pos), reveals })
}

pub fn verify(p: &Params, scheme: sig::Scheme, r_att: &H, cert: &Certificate) -> Result<(), String> {
    if cert.signed <= p.proven { return Err("signed <= proven".into()); }
    if cert.signed > p.total { return Err("signed weight exceeds total stake".into()); }
    if (cert.signed as f64) < p.min_ratio * p.proven as f64 { return Err("Ws/Wp below minimum ratio".into()); }
    if cert.n != p.n { return Err("attestor count mismatch".into()); }
    let k = num_reveals(p.lambda, p.log2q, cert.signed, p.proven, p.model);
    if cert.k != k { return Err("wrong k".into()); }
    // |P| <= k_rev: a certificate never needs more distinct reveals than coins
    if cert.reveals.is_empty() || cert.reveals.len() > k { return Err("too many reveals (|P| > k)".into()); }
    let mut depth = 0; while (1usize << depth) < cert.n { depth += 1; }
    // reveals must be sorted distinct
    for w in cert.reveals.windows(2) { if w[0].pos >= w[1].pos { return Err("unsorted reveals".into()); } }
    for r in &cert.reveals {
        if r.pos >= cert.n { return Err("pos out of range".into()); }
        if r.weight == 0 || r.l.checked_add(r.weight).map_or(true, |e| e > cert.signed) { return Err("bad interval".into()); }
    }
    // every coin must fall in some revealed interval, and every reveal must cover at least one coin
    let mut used = vec![false; cert.reveals.len()];
    for j in 0..k as u64 {
        let c = coin(j, &cert.r_sig, r_att, cert.signed, p.proven, p.msg, cert.n as u64);
        let mut covered = false;
        for (t, r) in cert.reveals.iter().enumerate() { if r.l <= c && c < r.l + r.weight { covered = true; used[t] = true; } }
        if !covered { return Err(format!("coin {} not covered", j)); }
    }
    if let Some(t) = used.iter().position(|u| !u) { return Err(format!("unused reveal at {}", cert.reveals[t].pos)); }
    // signatures
    for r in &cert.reveals { if !scheme.verify(&r.pk, p.msg, &r.sig) { return Err(format!("bad sig at {}", r.pos)); } }
    let pos: Vec<usize> = cert.reveals.iter().map(|r| r.pos).collect();
    let sl: Vec<H> = cert.reveals.iter().map(|r| keccak(&[LEAF, &sig_leaf(Some(&r.sig), r.l)])).collect();
    let al: Vec<H> = cert.reveals.iter().map(|r| keccak(&[LEAF, &att_leaf(&r.pk, r.weight)])).collect();
    if !Merkle::verify_multiproof(&cert.r_sig, depth, &pos, &sl, &cert.proof_sig) { return Err("sig merkle".into()); }
    if !Merkle::verify_multiproof(r_att, depth, &pos, &al, &cert.proof_att) { return Err("att merkle".into()); }
    Ok(())
}

/// Test helper: add one extra *valid* reveal (a signed slot not selected by any coin), keeping the
/// Merkle multiproofs consistent, so only the "every reveal is used" rule can reject it.
pub fn with_extra_reveal(c: &Certificate, pks: &[Vec<u8>], weights: &[u64], sigs: &[Option<Vec<u8>>], att: &Merkle) -> Option<Certificate> {
    let n = pks.len();
    let mut ls = vec![0u64; n]; let mut acc = 0u64;
    for i in 0..n { if sigs[i].is_some() { ls[i] = acc; acc += weights[i]; } }
    let extra = (0..n).find(|&i| sigs[i].is_some() && !c.reveals.iter().any(|r| r.pos == i))?;
    let st = Merkle::from_leaf_data(&(0..n).map(|i| sig_leaf(sigs[i].as_deref(), ls[i])).collect::<Vec<_>>());
    let mut bad = c.clone();
    bad.reveals.push(Reveal { pos: extra, pk: pks[extra].clone(), weight: weights[extra], sig: sigs[extra].clone().unwrap(), l: ls[extra] });
    bad.reveals.sort_by_key(|r| r.pos);
    let pos: Vec<usize> = bad.reveals.iter().map(|r| r.pos).collect();
    bad.proof_sig = st.multiproof(&pos); bad.proof_att = att.multiproof(&pos);
    Some(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn m44_fips204_roundtrip() {
        let s = sig::Scheme::M44;
        let (pk, sk) = s.keygen(&[3u8; 32]);
        assert_eq!((pk.len(), s.sig_len()), (1312, 2420));
        assert_eq!(s.keygen(&[3u8; 32]).0, pk); // keygen is deterministic in the seed
        let m = b"msg"; let sg = s.sign(&sk, m);
        assert_eq!(sg.len(), 2420); assert_eq!(s.sign(&sk, m), sg); // deterministic variant
        assert!(s.verify(&pk, m, &sg));
        assert!(!s.verify(&pk, b"msh", &sg));
        let mut bad = sg.clone(); bad[5] ^= 1; assert!(!s.verify(&pk, m, &bad));
        assert!(!s.verify(&pk[..1311], m, &sg));
    }

    #[test]
    fn extra_unused_reveal_rejected() {
        let scheme = sig::Scheme::D2; let n = 48;
        let w: Vec<u64> = (0..n as u64).map(|i| 1000 + 37 * i).collect();
        let total: u64 = w.iter().sum();
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|i| { let mut s = [0u8; 32]; s[0] = i as u8; scheme.keygen(&s) }).collect();
        let pks: Vec<Vec<u8>> = keys.iter().map(|k| k.0.clone()).collect();
        let att = Merkle::from_leaf_data(&(0..n).map(|i| att_leaf(&pks[i], w[i])).collect::<Vec<_>>());
        let msg = keccak(&[b"unit-test"]).to_vec();
        let sigs: Vec<Option<Vec<u8>>> = (0..n).map(|i| if i % 8 != 0 { Some(scheme.sign(&keys[i].1, &msg)) } else { None }).collect();
        // lambda kept small so that some signed slots stay unselected
        let p = Params { msg: &msg, proven: total / 3, lambda: 8.0, log2q: 2.0, model: Model::Classical, total, n, min_ratio: 1.1 };
        let c = build(&p, &pks, &w, &sigs, &att).unwrap();
        assert!(verify(&p, scheme, &att.root(), &c).is_ok());
        let bad = with_extra_reveal(&c, &pks, &w, &sigs, &att).expect("some signed slot unselected");
        let e = verify(&p, scheme, &att.root(), &bad).unwrap_err();
        assert!(e.contains("unused reveal") || e.contains("too many reveals"), "{}", e);
        // more reveals than coins is rejected as well
        let mut many = c.clone();
        while many.reveals.len() <= many.k { many.reveals.push(many.reveals[0].clone()); }
        assert!(verify(&p, scheme, &att.root(), &many).unwrap_err().contains("too many reveals"));
    }
}
