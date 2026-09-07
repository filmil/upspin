# TODO

Work items for this fork that have no owner yet.
Issues are disabled on the repository, so this file is the tracker.
Remove an item when it lands; add a link to the PR that closed it.

## Highest risk first: the key format flag day

The fourth review put this above everything else, and it is right.
Every part of the eepq change is contained by the `-eepq` flag except
one: a post-quantum public key has four lines, and every binary from
before the change parses exactly three.
One user rotating to such a key breaks every old client and server that
sees that user.
Decide, before the packing merges, whether the fix is a three line
keyserver record plus a separate ML-KEM record.
That decision changes the wire format of the key file again, and every
fixture under `testdata/pq*` with it; deciding after the merge means a
second migration.
Item 16 below has the details.

## Merge pipeline for cryptographic changes

These items come from a hostile review of the eepq post-quantum packing
(PR #59).
The review proposed a pipeline in which every stage blocks the merge:
static analysis, crypto unit tests, fuzz and race, compatibility, the
full test suite, human review, merge.
The nightly fuzz job is the only asynchronous input.

### Static analysis

1. **Run `go vet`, `staticcheck` and `gosec` on every PR.** Landed in
   PR #66. staticcheck runs the SA checks except SA1019; the S, ST and U
   checks and the deprecated crypto/elliptic calls in the ee packer
   remain open (see item 27).
2. **Run `govulncheck ./...` on every PR.** Landed in PR #63.
3. **Run `gitleaks` on the PR diff.** Landed in PR #64.
4. **Lint commit trailers.** Landed in PR #65.

### Crypto unit tests

5. **Golden wire format for ee and eepq.** Landed in PR #77.
6. **Combiner known answer vectors.** Landed in PR #78.
7. **Tamper matrix.** Landed in PR #82.
8. **Key and packing confusion.**
   `TestConfusion`, `TestCrossKeyPQ` and `TestUnpackWithoutDecapsulator`
   cover the wrong reader, eepq packdata as ee and the reverse, an
   ephemeral point on the wrong curve, a wrong-size ML-KEM ciphertext and
   a Factotum without `Decapsulator`.
   Still to do: the same cases for `Share`, `Countersign` and the
   `secret2.upspinkey` archive parser, with a named error kind for each.
9. **Allocation bound.** Landed in PR #74.

### Fuzz and race

10. **Fuzz targets with a committed corpus.**
    Targets: `FuzzUnmarshalEE`, `FuzzUnmarshalEEPQ`, `FuzzParsePublicKey`,
    `FuzzParsePrivateKey`, `FuzzSecret2Archive`, `FuzzProquintSeed`
    (PR #59 has `FuzzUnmarshal` for both packings).
    Commit the corpus under `testdata/fuzz`.
    Bazel does not drive the fuzz engine, so run this stage with plain
    `go test -fuzz` outside Bazel, 60 seconds per target on every PR.
    A nightly job runs one hour and opens a PR with new corpus entries.
11. **Coverage gate.**
    Fail the PR when `pack/ee`, `pack/packutil`, `factotum` or
    `key/keygen` fall below 90 percent line coverage, from
    `bazel coverage --combined_report=lcov`.
12. **Race detector.** Landed in PR #62.

### Compatibility

13. **Main binary against PR binary.** Landed in PR #84.
14. **Downgrade refusal test.** Landed in PR #76.

### From the third review

16. **The key format is not contained by the flag.**
    A post-quantum public key has four lines; every binary from before
    the change parses exactly three, so one user rotating breaks every
    old client and server that sees that user.
    Design a key record that publishes the classic three line key and
    holds the ML-KEM encapsulation key elsewhere, so that old binaries
    keep working, or accept and document the deployment-wide upgrade
    (documented for now in `doc/security.filmil.md`).
17. **A persistent switch.** Landed in PR #79.
18. **Golden entries for plain and eeintegrity.** Landed in PR #75.
19. **Wire `-race`, `govulncheck` and `gitleaks` into `bazel.yml`.**
    Landed in PRs #62, #63 and #64.

### From the fourth review

20. **Fuzz targets for the key parsers, with a committed corpus.** Landed in PR #73.
21. **Errors must name the process that lacks the flag.** Landed in PR #71.
22. **`requirepacking` and the upspinfs cache.** Landed in PR #70.
23. **`flags` imports `pack/ee` only to read and write the switch.** Landed in PR #68.
24. **`TestNonceUniquePQ` tests the random source, not the property.** Landed in PR #72.
25. **Tests that toggle process-wide state.** Landed in PR #69.
27. **Deprecated crypto/elliptic calls in the ee packer.**
    staticcheck SA1019 reports the packer's use of `elliptic.Marshal`
    and `ScalarMult`, which must stay byte for byte to keep stored data
    readable.
    Replacing them with `crypto/ecdh` is a cryptographic change that
    needs its own review; until then SA1019 is excluded in
    `staticcheck.conf`.
28. **staticcheck S, ST and U checks, and gosec below high/high.**
    The staticcheck findings were fixed and those checks enforced in
    PR #86, except the style checks ST1000, ST1003, ST1016 and ST1020,
    which the upstream code never followed.
    294 gosec findings below high severity and confidence (mostly G104
    unhandled errors and G115 integer conversions) are still reported
    but not gated.
    Fix them in small batches and raise the gate.
26. **Human review, for the fourth time.**
    Four rounds of review, all by an assistant.
    The parser, the combiner and the gating are in shape for a human
    cryptographer to read in an afternoon; nothing in this file
    substitutes for that reading.
    (Same as item 15.)

### Human review

15. **CODEOWNERS.**
    Name a human reviewer for `pack/`, `factotum/` and `key/` and require
    code owner review in the branch protection settings.
    Cryptographic code must not merge without a human reader.
    An assistant fixing an assistant's review does not count as reviewed.
