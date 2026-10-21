// SPDX-License-Identifier: MIT
// PQ-Vault: escrow contract whose release path depends only on Keccak and ML-DSA (FIPS 204).
// Research prototype accompanying the TDSC submission. NOT AUDITED.
pragma solidity ^0.8.25;

interface IMLDSA {
    function verify(bytes memory pk, bytes memory m, bytes memory signature, bytes memory ctx) external view returns (bool);
}

contract PQVault {
    struct Record {
        uint64 j;           // coin index
        uint32 pos;         // attestor position
        bytes32 pkHash;     // EXTCODEHASH of the SSTORE2 pointer holding the expanded ML-DSA key
        uint64 w;           // attestor weight
        bytes sig;          // ML-DSA-44 signature on M
        uint64 L;           // interval start
        bytes32[] sigPath;  // path to R_sig   (bound in the C_cert leaf)
        bytes32[] attPath;  // path to R_att   (bound in the C_cert leaf)
        bytes32[] certPath; // path to C_cert  (not part of the leaf)
    }

    /// Checkpoint header (static tuple: ABI-encoded in place, same calldata as the flat argument list).
    struct Header {
        uint256 e; bytes32 hBlock; bytes32 stateRoot; bytes32 omega; bytes32 rAttNext; bytes32 bindRoot; uint64 Wnext; uint64 Nnext;
    }

    struct Proposal {
        bytes32 M; bytes32 omega; bytes32 rAttNext; bytes32 rAtt; bytes32 rSig; bytes32 cCert;
        uint64 e; uint64 Ws; uint64 k; uint64 proposedAt;
        uint64 openDeadline; uint64 postedAt; uint32 nPosted; uint32 open; uint8 cDepth; uint8 status; bool allPending; bool allUsed;
        address relayer; uint64 W; uint8 depth;           // W, Wp, N, depth, rAtt: snapshot of the attestor set at propose time
        address allChallenger; uint64 Wp;
        uint64 N; uint64 Wnext; uint64 Nnext;
    } // status: 1 pending, 2 finalized, 3 rejected, 4 stale (bond refunded)

    struct Challenge { address challenger; uint64 deadline; uint8 state; } // 1 open, 2 answered, 3 paid on reject, 4 bond refunded

    IMLDSA public immutable mldsa;
    uint256 public constant TARGET_FP = uint256(260) << 64; // lambda + 2 log2 q + kappa_Q (128 + 128 + 4), 64.64 fixed point
    uint64 public constant KMAX = 4096;
    uint256 public constant BOND_R = 1 ether; uint256 public constant BOND_C = 0.1 ether;
    uint64 public constant T_CH = 7 days; uint64 public constant D_RESP = 1 days;
    uint64 public constant D_OPEN = 1 days; uint64 public constant D_POST = 2 days;
    uint256 public constant WDEPTH = 20; uint256 public constant SIGLEN = 2420;

    // current attestor set (updated at finalize)
    uint64 public W; uint64 public Wp; uint64 public N; uint8 public depth;
    bytes32 public rAtt;
    bytes32 public lastM;          // M of the latest finalized checkpoint (0 at deployment)
    uint256 public lastFinal;
    uint256 public nProps;
    mapping(uint256 => Proposal) internal props;
    mapping(uint256 => mapping(uint64 => Challenge)) public chals;
    mapping(uint256 => mapping(uint256 => uint256)) internal posted; // id => word => bitmap of posted coin indices
    mapping(bytes32 => bool) public spent;
    mapping(address => uint256) public owed;                          // pull payments (bonds and rewards)

    event Deposit(bytes32 indexed beta, uint256 amount);
    event Proposed(uint256 indexed id, uint256 indexed e, bytes32 M);
    event Rejected(uint256 indexed id, address to);

    constructor(IMLDSA _mldsa, bytes32 _rAtt, uint64 _W, uint64 _N) {
        require(_W >= 3 && _N >= 1 && _N <= (uint64(1) << 32), "set");
        mldsa = _mldsa; rAtt = _rAtt;
        _setSet(_W, _N);
    }

    function status(uint256 id) external view returns (uint8) { return props[id].status; }
    function epochOf(uint256 id) external view returns (uint64) { return props[id].e; }
    function msgOf(uint256 id) external view returns (bytes32) { return props[id].M; }
    function openCount(uint256 id) external view returns (uint32 open, uint32 nPosted, bool allPending) {
        Proposal storage c = props[id]; return (c.open, c.nPosted, c.allPending);
    }

    function challengeDeadline(uint256 id) public view returns (uint256 d) {
        Proposal storage c = props[id];
        d = uint256(c.proposedAt) + T_CH;
        if (c.postedAt != 0 && uint256(c.postedAt) + D_POST > d) d = uint256(c.postedAt) + D_POST;
    }

    /// The message signed by the attestors: binds chain, vault, epoch, the previous checkpoint and every header field.
    function checkpointMsg(Header calldata h, bytes32 prevM) public view returns (bytes32) {
        return keccak256(abi.encode("PQV-CP", block.chainid, address(this), h.e, prevM, h.hBlock, h.stateRoot,
            h.omega, h.rAttNext, h.bindRoot, h.Wnext, h.Nnext));
    }

    // ---------------- custody ----------------
    function deposit(bytes32 beta) external payable { emit Deposit(beta, msg.value); }

    function withdraw(uint256 id, address payable recipient, uint256 amount, uint64 nonce, uint256 index, bytes32[] calldata path) external {
        require(props[id].status == 2, "not final");
        require(path.length == WDEPTH && index < (uint256(1) << WDEPTH), "depth");
        bytes32 leaf = keccak256(abi.encodePacked(bytes1(0x00), address(this), block.chainid, recipient, amount, nonce));
        require(!spent[leaf], "spent");
        require(_climb(leaf, index, path) == props[id].omega, "bad proof");
        spent[leaf] = true; // effects before interaction
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "transfer");
    }

    /// Pull payment of bonds and rewards credited to msg.sender.
    function claim() external {
        uint256 a = owed[msg.sender];
        require(a > 0, "nothing");
        owed[msg.sender] = 0; // zero before the call
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok, "transfer");
    }

    // ---------------- checkpoints ----------------
    /// M is recomputed on chain from the header; k must equal the QROM rule ceil(260 / log2(Ws/Wp)) exactly.
    function propose(Header calldata h, bytes32 rSig, uint64 Ws, uint64 k, bytes32 cCert) external payable returns (uint256 id) {
        require(msg.value == BOND_R, "bond");
        require(h.e == lastFinal + 1, "epoch");
        require(h.Wnext >= 3 && h.Nnext >= 1 && h.Nnext <= (uint64(1) << 32), "next set");
        uint64 Wp_ = Wp;
        require(Ws <= W && uint256(Ws) * 10 >= uint256(Wp_) * 11, "Ws range");
        uint256 l = log2fp((uint256(Ws) << 64) / Wp_);
        require(k > 0 && k <= KMAX && uint256(k) * l >= TARGET_FP && uint256(k - 1) * l < TARGET_FP, "k");
        uint8 cd = 0; while ((uint256(1) << cd) < k) cd++;
        id = ++nProps;
        Proposal storage c = props[id];
        c.M = checkpointMsg(h, lastM);
        c.omega = h.omega; c.rAttNext = h.rAttNext; c.rAtt = rAtt; c.rSig = rSig; c.cCert = cCert;
        c.e = uint64(h.e); c.Ws = Ws; c.k = k; c.proposedAt = uint64(block.timestamp); c.cDepth = cd; c.status = 1;
        c.relayer = msg.sender; c.W = W; c.depth = depth; c.Wp = Wp_; c.N = N; c.Wnext = h.Wnext; c.Nnext = h.Nnext;
        emit Proposed(id, h.e, c.M);
    }

    function challenge(uint256 id, uint64 j) external payable {
        Proposal storage c = props[id];
        require(c.status == 1 && block.timestamp < challengeDeadline(id) && j < c.k, "closed");
        require(msg.value == BOND_C && chals[id][j].state == 0, "bond/dup");
        chals[id][j] = Challenge(msg.sender, uint64(block.timestamp) + D_RESP, 1);
        c.open++;
    }

    /// Open-all: demand that every committed record be posted (as calldata) within D_OPEN. No bond; once per proposal.
    function challengeAll(uint256 id) external {
        Proposal storage c = props[id];
        require(c.status == 1 && block.timestamp < challengeDeadline(id) && !c.allUsed, "closed");
        c.allUsed = true; c.allPending = true; c.openDeadline = uint64(block.timestamp) + D_OPEN; c.allChallenger = msg.sender;
    }

    /// Anyone posts committed records; only membership in C_cert is checked (Local is not evaluated here).
    function postRecords(uint256 id, Record[] calldata rs) external {
        Proposal storage c = props[id];
        require(c.status == 1 && c.allPending && block.timestamp <= c.openDeadline, "not open");
        uint256 n = c.nPosted;
        for (uint256 i = 0; i < rs.length; i++) {
            uint256 j = rs[i].j;
            require(j < c.k && _committed(c, rs[i]), "not committed");
            uint256 bit = uint256(1) << (j & 255);
            uint256 word = posted[id][j >> 8];
            if (word & bit != 0) continue; // duplicate (e.g. concurrent posters)
            posted[id][j >> 8] = word | bit; n++;
        }
        c.nPosted = uint32(n);
        if (n == c.k) { c.allPending = false; c.postedAt = uint64(block.timestamp); }
    }

    function timeoutAll(uint256 id) external {
        Proposal storage c = props[id];
        require(c.status == 1 && c.allPending && block.timestamp > c.openDeadline, "no timeout");
        _reject(id, c.allChallenger, BOND_R);
    }

    /// Answer a coin challenge with the committed record; one ML-DSA verification on chain. Callable by anyone.
    function respond(uint256 id, Record calldata r, address pkAddr) external {
        Proposal storage c = props[id];
        Challenge storage ch = chals[id][r.j];
        require(c.status == 1 && ch.state == 1 && block.timestamp <= ch.deadline, "no challenge");
        // (1) not the committed record => revert (a bad answer never rejects)
        require(_committed(c, r), "not committed");
        // (2) the committed record itself fails Local => reject
        if (!_localCore(c, r, true)) { ch.state = 3; _reject(id, ch.challenger, BOND_R + BOND_C); return; }
        // (3) wrong key pointer supplied by the caller => revert
        require(pkAddr.codehash == r.pkHash, "pk");
        // (4) ML-DSA verification of the committed signature on the recomputed M
        if (!mldsa.verify(abi.encodePacked(pkAddr), abi.encodePacked(c.M), r.sig, "")) {
            ch.state = 3; _reject(id, ch.challenger, BOND_R + BOND_C); return;
        }
        ch.state = 2; c.open--;
        owed[c.relayer] += BOND_C; // frivolous challenge: bond goes to the relayer
    }

    /// Anyone may reject a checkpoint whose challenge was not answered in time.
    function timeout(uint256 id, uint64 j) external {
        Challenge storage ch = chals[id][j];
        require(props[id].status == 1 && ch.state == 1 && block.timestamp > ch.deadline, "no timeout");
        ch.state = 3;
        _reject(id, ch.challenger, BOND_R + BOND_C);
    }

    /// Challengers whose challenge was still open when the proposal was rejected recover their bond.
    function refundChallenge(uint256 id, uint64 j) external {
        Challenge storage ch = chals[id][j];
        require(props[id].status == 3 && ch.state == 1, "no refund");
        ch.state = 4;
        owed[ch.challenger] += BOND_C;
    }

    function finalize(uint256 id) external {
        Proposal storage c = props[id];
        require(c.status == 1 && block.timestamp >= challengeDeadline(id), "window");
        require(c.open == 0 && !c.allPending, "open");
        if (c.e == lastFinal + 1) {
            c.status = 2; lastFinal = c.e; lastM = c.M; rAtt = c.rAttNext;
            _setSet(c.Wnext, c.Nnext);
        } else c.status = 4; // another proposal for this epoch was finalized first
        owed[c.relayer] += BOND_R;
    }

    /// Direct (non-optimistic) verification of a full certificate, for comparison.
    function verifyDirect(uint256 id, Record[] calldata rs, address[] calldata pkAddrs) external view returns (bool) {
        Proposal storage c = props[id];
        require(c.status != 0 && rs.length == c.k && pkAddrs.length == rs.length, "count");
        uint256 n = c.N;
        uint256[] memory done = new uint256[]((n + 255) / 256);
        for (uint256 i = 0; i < rs.length; i++) {
            Record calldata r = rs[i];
            require(r.j == i, "order");
            uint256 p = r.pos;
            if (p >= n || r.sig.length != SIGLEN) return false;
            bool fresh = (done[p >> 8] >> (p & 255)) & 1 == 0;   // each position's signature and paths checked once
            if (fresh) done[p >> 8] |= uint256(1) << (p & 255);
            else {
                // a repeated position must carry the same (pkHash, w, L) as its first, fully checked, occurrence
                uint256 t = i; while (rs[--t].pos != p) {}
                if (rs[t].w != r.w || rs[t].L != r.L || rs[t].pkHash != r.pkHash) return false;
            }
            if (!_localCore(c, r, fresh)) return false;
            if (fresh && (pkAddrs[i].codehash != r.pkHash
                || !mldsa.verify(abi.encodePacked(pkAddrs[i]), abi.encodePacked(c.M), r.sig, ""))) return false;
        }
        return true;
    }

    // ---------------- internals ----------------
    function _setSet(uint64 w, uint64 n) internal {
        uint8 d = 0; while ((uint256(1) << d) < n) d++;
        W = w; Wp = w / 3; N = n; depth = d;
    }

    function _reject(uint256 id, address to, uint256 amount) internal {
        props[id].status = 3;
        owed[to] += amount;
        emit Rejected(id, to);
    }

    /// C_cert leaf binds every field used by Local, including both Merkle paths; certPath must have length ceil(log2 k).
    function _committed(Proposal storage c, Record calldata r) internal view returns (bool) {
        if (r.certPath.length != c.cDepth) return false;
        bytes32 leaf = keccak256(abi.encode(r.j, r.pos, r.pkHash, r.w, keccak256(r.sig), r.L,
            keccak256(abi.encodePacked(r.sigPath)), keccak256(abi.encodePacked(r.attPath))));
        return _climb(leaf, r.j, r.certPath) == c.cCert;
    }

    /// Local predicate on committed data (without the ML-DSA check), against the proposal's snapshot. Never reverts.
    function _localCore(Proposal storage c, Record calldata r, bool full) internal view returns (bool) {
        if (r.j >= c.k || r.pos >= c.N || r.w == 0 || uint256(r.L) + r.w > c.Ws) return false;
        uint256 coin = uint256(uint128(bytes16(keccak256(abi.encodePacked(
            "CCOK-COIN-v2", r.j, c.rSig, c.rAtt, c.Ws, c.Wp, c.N, c.M))))) % c.Ws;
        if (coin < r.L || coin >= uint256(r.L) + r.w) return false;
        if (!full) return true;
        uint256 d = c.depth;
        if (r.sig.length != SIGLEN || r.sigPath.length != d || r.attPath.length != d) return false;
        bytes32 sigLeaf = keccak256(abi.encodePacked(bytes1(0x00), bytes1(0x01), r.sig, r.L));
        if (_climb(sigLeaf, r.pos, r.sigPath) != c.rSig) return false;
        bytes32 attLeaf = keccak256(abi.encodePacked(bytes1(0x00), r.pkHash, r.w));
        return _climb(attLeaf, r.pos, r.attPath) == c.rAtt;
    }

    /// Index-aware Merkle climb with node prefix 0x01.
    function _climb(bytes32 leaf, uint256 idx, bytes32[] calldata path) internal pure returns (bytes32 node) {
        node = leaf;
        for (uint256 i = 0; i < path.length; i++) {
            node = (idx & 1) == 0 ? keccak256(abi.encodePacked(bytes1(0x01), node, path[i]))
                                  : keccak256(abi.encodePacked(bytes1(0x01), path[i], node));
            idx >>= 1;
        }
    }

    /// log2 of a 64.64 fixed-point number x >= 1, result in 64.64 (32 fractional bits of precision).
    function log2fp(uint256 x) public pure returns (uint256 r) {
        require(x >= 1 << 64, "x<1");
        uint256 n = 0; uint256 y = x >> 64;
        while (y > 1) { y >>= 1; n++; }
        r = n << 64; y = x >> n;
        for (uint256 i = 0; i < 32; i++) {
            y = (y * y) >> 64;
            if (y >= 2 << 64) { y >>= 1; r |= uint256(1) << (63 - i); }
        }
    }
}
