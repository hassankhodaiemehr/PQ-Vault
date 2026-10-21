// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SSTORE2} from "sstore2/SSTORE2.sol";
import {ZKNOX_dilithium} from "../src/ZKNOX_dilithium.sol";
import {PQVault, IMLDSA} from "../src/PQVault.sol";

contract PQVaultTest is Test {
    struct V {
        uint64 W; uint64 Wp; uint64 N; bytes32 M; bytes32 rAtt; bytes32 rSig; uint64 Ws; uint64 k; bytes32 cCert;
        uint32[] distinct; bytes[] pkdata; PQVault.Record[] records; bytes32 omega; address recipient; uint256 amount; uint64 nonce;
        uint256 windex; bytes32[] wpath; address vaultAddr; uint256 chainId;
        bytes32 hBlock; bytes32 stateRoot; bytes32 rAttNext; bytes32 bindRoot; uint64 Wnext; uint64 Nnext;
    }

    ZKNOX_dilithium mldsa;
    PQVault vault;
    V v;
    mapping(uint32 => address) pkAddr;
    address constant THIRD = address(0xBEEF);

    function _cdCost(bytes memory cd) internal pure returns (uint256 std, uint256 floor_) {
        uint256 z; for (uint256 i = 0; i < cd.length; i++) if (cd[i] == 0) z++;
        uint256 tokens = z + 4 * (cd.length - z);
        std = 4 * tokens; floor_ = 10 * tokens;
    }

    function _txTotal(bytes memory cd, uint256 exec) internal pure returns (uint256) {
        (uint256 std, uint256 fl) = _cdCost(cd);
        return 21000 + (std + exec > fl ? std + exec : fl);
    }

    function _report(string memory name, bytes memory cd, uint256 exec) internal pure {
        console.log(string.concat("GAS ", name, " exec/calldataBytes/txTotal:"), exec, cd.length, _txTotal(cd, exec));
    }

    function setUp() public {
        bytes memory raw = vm.readFileBinary("vault/vectors.bin");
        V memory d = abi.decode(raw, (V));
        v.W = d.W; v.Wp = d.Wp; v.N = d.N; v.M = d.M; v.rAtt = d.rAtt; v.rSig = d.rSig; v.Ws = d.Ws; v.k = d.k; v.cCert = d.cCert;
        v.omega = d.omega; v.recipient = d.recipient; v.amount = d.amount; v.nonce = d.nonce; v.windex = d.windex;
        v.vaultAddr = d.vaultAddr; v.chainId = d.chainId;
        v.hBlock = d.hBlock; v.stateRoot = d.stateRoot; v.rAttNext = d.rAttNext; v.bindRoot = d.bindRoot; v.Wnext = d.Wnext; v.Nnext = d.Nnext;
        for (uint256 i = 0; i < d.wpath.length; i++) v.wpath.push(d.wpath[i]);
        for (uint256 i = 0; i < d.records.length; i++) v.records.push(d.records[i]);
        for (uint256 i = 0; i < d.distinct.length; i++) { v.distinct.push(d.distinct[i]); pkAddr[d.distinct[i]] = SSTORE2.write(d.pkdata[i]); }
        mldsa = new ZKNOX_dilithium();
        // fixed address so that withdrawal leaves (which bind address(this) and chainid) match the generated tree
        vm.chainId(d.chainId);
        deployCodeTo("PQVault.sol:PQVault", abi.encode(IMLDSA(address(mldsa)), d.rAtt, d.W, d.N), d.vaultAddr);
        vault = PQVault(d.vaultAddr);
        vm.deal(address(this), 100 ether);
        vm.deal(THIRD, 10 ether);
        vm.deal(address(vault), 10 ether);
    }

    receive() external payable {}

    function _hdr() internal view returns (PQVault.Header memory) {
        return PQVault.Header(1, v.hBlock, v.stateRoot, v.omega, v.rAttNext, v.bindRoot, v.Wnext, v.Nnext);
    }

    function _propose() internal returns (uint256 id) { id = _propose(_hdr(), v.cCert, true); }
    function _propose(bytes32 cCert, bool rep) internal returns (uint256 id) { id = _propose(_hdr(), cCert, rep); }

    function _propose(PQVault.Header memory h, bytes32 cCert, bool rep) internal returns (uint256 id) {
        bytes memory cd = abi.encodeCall(PQVault.propose, (h, v.rSig, v.Ws, v.k, cCert));
        uint256 g = gasleft();
        id = vault.propose{value: 1 ether}(h, v.rSig, v.Ws, v.k, cCert);
        if (rep) _report("propose", cd, g - gasleft());
    }

    function _rec(uint64 j) internal view returns (PQVault.Record memory) { return v.records[j]; }

    function testKeyRegistrationCost() public {
        V memory d = abi.decode(vm.readFileBinary("vault/vectors.bin"), (V));
        uint256 g = gasleft(); SSTORE2.write(d.pkdata[0]); uint256 used = g - gasleft();
        console.log("GAS register expanded ML-DSA-44 key (SSTORE2) exec/bytes:", used, d.pkdata[0].length);
    }

    function testHappyPathAndWithdraw() public {
        uint256 g = gasleft(); vault.deposit{value: 1 ether}(bytes32(uint256(42)));
        _report("deposit", abi.encodeCall(PQVault.deposit, (bytes32(uint256(42)))), g - gasleft());
        uint256 id = _propose();
        vm.warp(vm.getBlockTimestamp() + 7 days);
        g = gasleft(); vault.finalize(id);
        _report("finalize", abi.encodeCall(PQVault.finalize, (id)), g - gasleft());
        assertEq(vault.status(id), 2); assertEq(vault.lastFinal(), 1); assertEq(vault.rAtt(), v.rAttNext);
        assertEq(vault.msgOf(id), v.M); assertEq(vault.lastM(), v.M);   // on-chain M equals the signed M
        assertEq(vault.W(), v.Wnext); assertEq(vault.Wp(), v.Wnext / 3); assertEq(vault.N(), v.Nnext); assertEq(vault.depth(), 16);
        assertEq(vault.owed(address(this)), 1 ether);
        g = gasleft(); vault.claim();
        _report("claim", abi.encodeCall(PQVault.claim, ()), g - gasleft());
        assertEq(vault.owed(address(this)), 0);
        bytes32[] memory wp = v.wpath;
        bytes memory cd = abi.encodeCall(PQVault.withdraw, (id, payable(v.recipient), v.amount, v.nonce, v.windex, wp));
        g = gasleft(); vault.withdraw(id, payable(v.recipient), v.amount, v.nonce, v.windex, wp);
        _report("withdraw", cd, g - gasleft());
        assertEq(v.recipient.balance, v.amount);
    }

    // (g) a withdrawal leaf pays once
    function testWithdrawOnlyOnce() public {
        uint256 id = _propose();
        bytes32[] memory wp = v.wpath;
        vm.expectRevert(bytes("not final"));
        vault.withdraw(id, payable(v.recipient), v.amount, v.nonce, v.windex, wp);
        vm.warp(vm.getBlockTimestamp() + 7 days); vault.finalize(id);
        vm.expectRevert(bytes("bad proof")); // wrong index
        vault.withdraw(id, payable(v.recipient), v.amount, v.nonce, v.windex ^ 1, wp);
        vault.withdraw(id, payable(v.recipient), v.amount, v.nonce, v.windex, wp);
        assertEq(v.recipient.balance, v.amount);
        vm.expectRevert(bytes("spent"));
        vault.withdraw(id, payable(v.recipient), v.amount, v.nonce, v.windex, wp);
        assertEq(v.recipient.balance, v.amount);
    }

    function testDisputeHonestRelayer() public {
        uint256 id = _propose();
        uint64 j = 5;
        bytes memory cdc = abi.encodeCall(PQVault.challenge, (id, j));
        uint256 g = gasleft(); vault.challenge{value: 0.1 ether}(id, j);
        _report("challenge", cdc, g - gasleft());
        PQVault.Record memory r = _rec(j);
        bytes memory cd = abi.encodeCall(PQVault.respond, (id, r, pkAddr[r.pos]));
        g = gasleft(); vault.respond(id, r, pkAddr[r.pos]);
        _report("respond (one ML-DSA verify)", cd, g - gasleft());
        assertEq(vault.status(id), 1); // still pending: honest answer
        (uint32 open,,) = vault.openCount(id); assertEq(open, 0);
    }

    function testDisputeForgedRecordRejected() public {
        uint256 id = _propose(); uint64 j = 3;
        vault.challenge{value: 0.1 ether}(id, j);
        PQVault.Record memory r = _rec(j);
        r.sig[100] = r.sig[100] ^ 0x01; // tampered signature no longer matches C_cert
        vm.expectRevert(bytes("not committed"));
        vault.respond(id, r, pkAddr[r.pos]);
        vm.warp(vm.getBlockTimestamp() + 1 days + 1);
        vault.timeout(id, j);
        assertEq(vault.status(id), 3);
    }

    // (a) a third party answering with the committed record but a wrong key pointer reverts and never rejects
    function testThirdPartyWrongPkAddrReverts() public {
        uint256 id = _propose(); uint64 j = 7;
        vault.challenge{value: 0.1 ether}(id, j);
        PQVault.Record memory r = _rec(j);
        uint32 other = v.distinct[0] == r.pos ? v.distinct[1] : v.distinct[0];
        vm.prank(THIRD); vm.expectRevert(bytes("pk"));
        vault.respond(id, r, pkAddr[other]);          // another attestor's key
        vm.prank(THIRD); vm.expectRevert(bytes("pk"));
        vault.respond(id, r, address(0xdead));        // empty account
        assertEq(vault.status(id), 1);
        (,, uint8 st) = vault.chals(id, j); assertEq(st, 1);
        vm.prank(THIRD); vault.respond(id, r, pkAddr[r.pos]); // anyone can give the right answer
        (,, st) = vault.chals(id, j); assertEq(st, 2);
        assertEq(vault.status(id), 1);
    }

    // (b) a record whose sigPath differs from the committed one is not the committed record: revert
    function testTamperedSigPathReverts() public {
        uint256 id = _propose(); uint64 j = 9;
        vault.challenge{value: 0.1 ether}(id, j);
        PQVault.Record memory r = _rec(j);
        r.sigPath[0] = bytes32(uint256(r.sigPath[0]) ^ 1);
        vm.expectRevert(bytes("not committed"));
        vault.respond(id, r, pkAddr[r.pos]);
        r = _rec(j); r.attPath[3] = bytes32(0);
        vm.expectRevert(bytes("not committed"));
        vault.respond(id, r, pkAddr[r.pos]);
        r = _rec(j);
        bytes32[] memory longer = new bytes32[](r.certPath.length + 1);
        for (uint256 i = 0; i < r.certPath.length; i++) longer[i] = r.certPath[i];
        r.certPath = longer;
        vm.expectRevert(bytes("not committed"));
        vault.respond(id, r, pkAddr[r.pos]);
        assertEq(vault.status(id), 1);
    }

    // relayer committed (in C_cert) to a record that fails Local: answering it rejects the checkpoint
    function testCommittedBadRecordRejects() public {
        uint64 j = 11;
        PQVault.Record memory r = _rec(j);
        r.L = r.L + 1; // interval no longer matches R_sig
        bytes32 node = keccak256(abi.encode(r.j, r.pos, r.pkHash, r.w, keccak256(r.sig), r.L,
            keccak256(abi.encodePacked(r.sigPath)), keccak256(abi.encodePacked(r.attPath))));
        uint256 idx = j;
        for (uint256 i = 0; i < r.certPath.length; i++) {
            node = (idx & 1) == 0 ? keccak256(abi.encodePacked(bytes1(0x01), node, r.certPath[i]))
                                  : keccak256(abi.encodePacked(bytes1(0x01), r.certPath[i], node));
            idx >>= 1;
        }
        uint256 id = _propose(node, false);
        vm.prank(THIRD); vault.challenge{value: 0.1 ether}(id, j);
        vault.respond(id, r, pkAddr[r.pos]);
        assertEq(vault.status(id), 3);
        assertEq(vault.owed(THIRD), 1.1 ether);
        uint256 b = THIRD.balance;
        vm.prank(THIRD); vault.claim();
        assertEq(THIRD.balance, b + 1.1 ether); assertEq(vault.owed(THIRD), 0);
        vm.prank(THIRD); vm.expectRevert(bytes("nothing")); vault.claim();
    }

    // (c) finalize is blocked while a challenge is open and goes through once it is answered
    function testFinalizeBlockedWhileOpen() public {
        uint256 t0 = vm.getBlockTimestamp();
        uint256 id = _propose(); uint64 j = 2;
        vm.warp(t0 + 6 days + 12 hours);
        vault.challenge{value: 0.1 ether}(id, j);
        vm.warp(t0 + 7 days);
        vm.expectRevert(bytes("open"));
        vault.finalize(id);
        PQVault.Record memory r = _rec(j);
        vault.respond(id, r, pkAddr[r.pos]);
        vault.finalize(id);
        assertEq(vault.status(id), 2);
    }

    // (d) a late, unanswered challenge just before T_CH leads to rejection; finalize cannot win the race
    function testLateChallengeTimeout() public {
        uint256 t0 = vm.getBlockTimestamp();
        uint256 id = _propose(); uint64 j = 4;
        vm.warp(t0 + 7 days - 1);
        vm.prank(THIRD); vault.challenge{value: 0.1 ether}(id, j);
        vm.warp(t0 + 7 days);
        vm.expectRevert(bytes("closed"));
        vault.challenge{value: 0.1 ether}(id, 5);    // window closed for new challenges
        vm.expectRevert(bytes("open"));
        vault.finalize(id);
        vm.warp(t0 + 7 days - 1 + 1 days);
        vm.expectRevert(bytes("no timeout"));
        vault.timeout(id, j);                         // deadline not passed yet
        vm.expectRevert(bytes("open"));
        vault.finalize(id);
        vm.warp(t0 + 8 days);
        vault.timeout(id, j);
        assertEq(vault.status(id), 3);
        assertEq(vault.owed(THIRD), 1.1 ether);
        vm.expectRevert(bytes("window"));
        vault.finalize(id);
    }

    function _postAll(uint256 id) internal {
        uint256 k = v.records.length; uint256 i0 = 0; uint256 nTx = 0; uint256 totBytes = 0; uint256 totGas = 0; uint256 totExec = 0;
        while (i0 < k) {
            uint256 sz = 100; uint256 i1 = i0;   // selector + id + offset + length = 100 bytes
            while (i1 < k) { uint256 s = abi.encode(v.records[i1]).length; if (sz + s > 128 * 1024) break; sz += s; i1++; }
            PQVault.Record[] memory batch = new PQVault.Record[](i1 - i0);
            for (uint256 t = i0; t < i1; t++) batch[t - i0] = v.records[t];
            bytes memory cd = abi.encodeCall(PQVault.postRecords, (id, batch));
            assertLe(cd.length, 128 * 1024);
            vault.postRecords(id, batch);
            // callee gas only: a gasleft() delta here would include the harness's growing memory (ABI-encoding 128 KB batches)
            uint256 used = vm.lastCallGas().gasTotalUsed;
            _report(string.concat("postRecords batch ", vm.toString(nTx), " (", vm.toString(i1 - i0), " records)"), cd, used);
            nTx++; totBytes += cd.length; totGas += _txTotal(cd, used); totExec += used; i0 = i1;
        }
        console.log("OPENALL k / txs (<=128KB each) / total calldata bytes:", k, nTx, totBytes);
        console.log("OPENALL total exec gas / total tx gas (EIP-7623):", totExec, totGas);
    }

    // (e) open-all: post every committed record as calldata, in batches that fit a 128 KB transaction
    function testOpenAll() public {
        uint256 t0 = vm.getBlockTimestamp();
        uint256 id = _propose();
        vm.warp(t0 + 6 days);
        vm.prank(THIRD);
        uint256 g = gasleft(); vault.challengeAll(id);
        _report("challengeAll", abi.encodeCall(PQVault.challengeAll, (id)), g - gasleft());
        vm.expectRevert(bytes("closed"));
        vault.challengeAll(id);
        vm.warp(t0 + 6 days + 1 hours);
        vm.warp(t0 + 7 days);
        vm.expectRevert(bytes("open"));
        vault.finalize(id);                           // pending open-all blocks finalization
        vm.warp(t0 + 6 days + 1 hours);
        _postAll(id);
        uint256 k = v.records.length;
        (uint32 open, uint32 nPosted, bool allPending) = vault.openCount(id);
        assertEq(open, 0); assertEq(nPosted, k); assertFalse(allPending);
        uint256 dl = vault.challengeDeadline(id);
        assertEq(dl, t0 + 6 days + 1 hours + 2 days);
        vm.warp(t0 + 7 days);
        vm.expectRevert(bytes("window"));
        vault.finalize(id);                           // extended window still open
        vault.challenge{value: 0.1 ether}(id, 1);     // watchers can still challenge a posted index
        PQVault.Record memory r = _rec(1);
        vault.respond(id, r, pkAddr[r.pos]);
        vm.warp(dl);
        vault.finalize(id);
        assertEq(vault.status(id), 2);
    }

    function testOpenAllTimeout() public {
        uint256 id = _propose();
        vm.prank(THIRD); vault.challengeAll(id);
        PQVault.Record[] memory batch = new PQVault.Record[](10);
        for (uint256 t = 0; t < 10; t++) batch[t] = v.records[t];
        vault.postRecords(id, batch);
        vault.postRecords(id, batch);                 // duplicates are ignored
        (, uint32 nPosted,) = vault.openCount(id); assertEq(nPosted, 10);
        vm.warp(vm.getBlockTimestamp() + 1 days + 1);
        vm.expectRevert(bytes("not open"));
        vault.postRecords(id, batch);
        vault.timeoutAll(id);
        assertEq(vault.status(id), 3);
        assertEq(vault.owed(THIRD), 1 ether);
    }

    // (f) a rejected epoch can be re-proposed; a second proposal for a finalized epoch becomes stale
    function testReproposeAfterReject() public {
        uint256 id1 = _propose(); uint64 j = 6;
        vault.challenge{value: 0.1 ether}(id1, j);
        vm.warp(vm.getBlockTimestamp() + 1 days + 1);
        vault.timeout(id1, j);
        assertEq(vault.status(id1), 3);
        uint256 t1 = vm.getBlockTimestamp();
        uint256 id2 = _propose(v.cCert, false);
        uint256 id3 = _propose(v.cCert, false);      // competing proposal for the same epoch
        assertEq(id2, 2); assertEq(id3, 3); assertEq(vault.epochOf(id2), 1);
        vm.warp(t1 + 7 days);
        vault.finalize(id2);
        assertEq(vault.status(id2), 2); assertEq(vault.lastFinal(), 1);
        uint256 b = vault.owed(address(this));
        vault.finalize(id3);
        assertEq(vault.status(id3), 4); assertEq(vault.owed(address(this)), b + 1 ether);
        PQVault.Header memory h = _hdr();
        vm.expectRevert(bytes("epoch"));
        vault.propose{value: 1 ether}(h, v.rSig, v.Ws, v.k, v.cCert);
    }

    // review item 1: the header is bound to M. Substituting omega (same rSig/cCert) changes M,
    // so the honest records no longer satisfy Local / the signature check, and any challenge rejects.
    function testOmegaSubstitutionRejected() public {
        PQVault.Header memory h = _hdr();
        assertEq(vault.checkpointMsg(h, bytes32(0)), v.M);
        h.omega = keccak256("attacker withdrawal root");
        uint256 id = _propose(h, v.cCert, false);
        assertTrue(vault.msgOf(id) != v.M);
        uint64 j = 0;
        vm.prank(THIRD); vault.challenge{value: 0.1 ether}(id, j);
        PQVault.Record memory r = _rec(j);
        vault.respond(id, r, pkAddr[r.pos]);          // honest committed record: coin and/or ML-DSA check fails on M'
        assertEq(vault.status(id), 3);
        assertEq(vault.owed(THIRD), 1.1 ether);
        // every other header field is bound the same way
        PQVault.Header memory h2 = _hdr(); h2.rAttNext = bytes32(uint256(1));
        assertTrue(vault.checkpointMsg(h2, bytes32(0)) != v.M);
        h2 = _hdr(); h2.Wnext = v.Wnext + 1;
        assertTrue(vault.checkpointMsg(h2, bytes32(0)) != v.M);
        h2 = _hdr(); h2.e = 2;
        assertTrue(vault.checkpointMsg(h2, bytes32(0)) != v.M);
        assertTrue(vault.checkpointMsg(_hdr(), bytes32(uint256(1))) != v.M);
    }

    // review item 3: k must equal ceil(260 / log2(Ws/Wp)) exactly
    function testExactK() public {
        PQVault.Header memory h = _hdr();
        vm.expectRevert(bytes("k"));
        vault.propose{value: 1 ether}(h, v.rSig, v.Ws, v.k + 1, v.cCert);
        vm.expectRevert(bytes("k"));
        vault.propose{value: 1 ether}(h, v.rSig, v.Ws, v.k - 1, v.cCert);
        vault.propose{value: 1 ether}(h, v.rSig, v.Ws, v.k, v.cCert);
    }

    function testDirectVerification() public {
        uint256 id = _propose();
        PQVault.Record[] memory rs = v.records;
        address[] memory addrs = new address[](rs.length);
        for (uint256 i = 0; i < rs.length; i++) addrs[i] = pkAddr[rs[i].pos];
        bytes memory cd = abi.encodeCall(PQVault.verifyDirect, (id, rs, addrs));
        uint256 g = gasleft(); bool ok = vault.verifyDirect(id, rs, addrs); uint256 used = g - gasleft();
        assertTrue(ok);
        _report("verifyDirect (all coins)", cd, used);
        console.log("distinct reveals / coins:", v.distinct.length, rs.length);
    }

    function testLog2() public view {
        uint256 g = gasleft(); uint256 r = vault.log2fp((uint256(3) << 64)); uint256 used = g - gasleft();
        console.log("log2(3) * 1e6 and gas:", (r * 1e6) >> 64, used);
    }
}
