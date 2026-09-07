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

5. **Golden wire format for ee and eepq.**
   PR #59 adds `pack/ee/testdata/ee-golden.json`, written by the code at
   the fork point, and `eepq-golden.json`, written by the branch; a test
   unpacks each.
   Still to do: a byte-level golden of `packdata.Marshal` for a fixed
   struct under both packings, so that a change to one byte fails and the
   fixture must be updated on purpose.
6. **Combiner known answer vectors.**
   `TestStrongKeyVectors` pins the output of `strongKey` for fixed inputs
   per key type.
   Still to do: move the vectors and their inputs to a testdata file that
   another implementation can check, and document how to regenerate them.
   ML-KEM itself is not tested; `crypto/mlkem` runs the FIPS 203 vectors.
7. **Tamper matrix.**
   `TestTamperMatrix` flips the first and last bit of every packdata
   field and checks that `Unpack` rejects the result under both packings.
   Still to do: entries with several readers and the all-users wrap, and
   the same matrix for `Name`, `SetTime` and `Countersign`.
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

13. **Main binary against PR binary.**
    Check out `origin/main` in a worktree, build its `upspin` binary, and
    with `upbox` have the old binary write `ee` files that the new binary
    reads, then the reverse.
    This makes "ee is untouched on the wire" something a machine checks.
    About five minutes.
14. **Downgrade refusal test.**
    With `requirepacking: eepq` in the config, serve an `ee` entry from a
    fake directory server and assert that `Get` and `Open` fail with
    `errors.Permission`; also the write side with a config whose
    `packing` line says `ee`.

### From the third review

16. **The key format is not contained by the flag.**
    A post-quantum public key has four lines; every binary from before
    the change parses exactly three, so one user rotating breaks every
    old client and server that sees that user.
    Design a key record that publishes the classic three line key and
    holds the ML-KEM encapsulation key elsewhere, so that old binaries
    keep working, or accept and document the deployment-wide upgrade
    (documented for now in `doc/security.filmil.md`).
17. **A persistent switch.**
    `signup` writes `packing: eepq` into the config, and config parsing
    refuses that line without `-eepq`, so every later invocation needs
    the flag.
    Add an environment variable or a config key such as
    `experimental: eepq` as an equivalent opt-in that persists; an
    explicit line in the user's own config is the same consent as a
    flag.
18. **Golden entries for plain and eeintegrity.** Landed in PR #75.
19. **Wire `-race`, `govulncheck` and `gitleaks` into `bazel.yml`.**
    Landed in PRs #62, #63 and #64.

### From the fourth review

20. **Fuzz targets for the key parsers, with a committed corpus.**
    `ParsePublicKey`, `ParseEncapsulationKey`, `parsePrivateKey` and the
    `secret2.upspinkey` archive parser were rewritten, and `ParsePublicKey`
    runs on every key a client fetches from a keyserver, which is
    untrusted input in the same sense as packdata.
    The change has one fuzz target, `FuzzUnmarshal`, with three seeds and
    no corpus directory.
    Add `FuzzParsePublicKey`, `FuzzParseEncapsulationKey`,
    `FuzzParsePrivateKey`, `FuzzSecret2Archive` and
    `FuzzSecretFromProquint`, and commit a `testdata/fuzz` corpus so that
    a crasher found once stays a regression test.
    (Overlaps item 10.)
21. **Errors must name the process that lacks the flag.** Landed in PR #71.
22. **`requirepacking` and the upspinfs cache.** Landed in PR #70.
23. **`flags` imports `pack/ee` only to read and write the switch.** Landed in PR #68.
24. **`TestNonceUniquePQ` tests the random source, not the property.** Landed in PR #72.
25. **Tests that toggle process-wide state.** Landed in PR #69.
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
