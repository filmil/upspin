# Security: additions in this fork

This file holds the additions this fork makes to
[doc/security.md](security.md).
That file is the original Upspin text and is left as the original
authors wrote it.
The text here was written for the fork, with far less review than the
original, and describes the `eepq` packing added in
[README.filmil.md](../README.filmil.md).
Read the original first; the section below assumes its terms.

## Post-quantum key wrapping

The packing **eepq** is for users who expect an attacker to store their
ciphertext today and decrypt it once a large quantum computer exists.
Such an attacker recovers *dkey* from the ECDH wrapping described above,
because Shor's algorithm solves the discrete logarithm on P-256.
The AES-256 encryption of the file contents is not at risk, since Grover's
algorithm only halves its effective key length, to 128 bits.
So **eepq** changes only the wrapping of *dkey*.
Data encryption, checksums, and signatures stay as in **ee**.

Under **eepq** each user key pairs an elliptic curve with an ML-KEM key,
the key encapsulation mechanism standardized in FIPS 203.
The key type names both, and each curve pairs with the ML-KEM parameter
set of matching strength: `p256+mlkem768`, `p384+mlkem768` and
`p521+mlkem1024`.
The public key file gains a fourth line holding the ML-KEM encapsulation
key, and the private key file gains a second line holding the ML-KEM seed.
Alice wraps *dkey* for Bob by running both mechanisms.
She computes the ECDH shared point S with an ephemeral key V as before.
She also encapsulates to Bob's ML-KEM key, which yields a shared secret K
and a ciphertext C.
HKDF-SHA256 then derives *strong* from the concatenation of K, S, V,
Bob's public point, C and a fixed label.
The info string names the packing, the hash of Bob's public key, and the
nonce.
Each part is prefixed by its length, so the keying material has one
parse whatever the sizes.
This is an HKDF concatenation combiner in the style of X-Wing
(draft-connolly-cfrg-xwing-kem).
It is not X-Wing: it uses a NIST curve instead of X25519 and HKDF-SHA256
instead of SHA3-256, and it has no security proof of its own.
The wrapping becomes

```
W(dkey,U) = {sha256(P(U)), nonce, V, C, aes(dkey,strong)}
```

Bob unwraps by computing S with his elliptic curve private key and K by
decapsulating C with his ML-KEM private key.
An attacker must break both ECDH and ML-KEM to recover *strong*.

Signatures remain ECDSA.
A signature only needs to resist forgery while the file is in use, not for
decades after it was stored.
An **eepq** writer can only wrap for readers whose keys have an ML-KEM
component.
Both `put` and `share -fix` refuse to proceed, naming the reader, when an
Access file grants read access to a user whose key is classic.
The owner then gives that reader a post-quantum key, removes the reader,
or uses **ee**.

The packing is opt-in, and the switch is per process.
Every binary needs the `-eepq` flag before it will read or write
**eepq** entries, accept `packing: eepq`, or generate a post-quantum key.
That includes the servers.
A directory server started without the flag rejects **eepq** entries as
invalid.
A directory server, cache server, store server or `upspinfs` started
without it cannot read an Access or Group file that a post-quantum user
wrote under **eepq**, so that user's tree fails access checks through it.
Every failure names the flag.
The switch is one process-wide value in the `pack` registry; the flag
sets it, and it is advisory, since any code in the process can set it.
The `-curve` flag of `keygen` and `signup` keeps its name for
compatibility, but it now names a key type, which may include a KEM.

The flag does not contain the key format.
A post-quantum public key has four lines, and a binary from before this
change parses only three.
Once a user rotates to such a key, every old binary in the deployment
fails on that user.
An old client cannot share even an **ee** file with them.
An old directory server cannot verify their signatures, so their whole
tree fails access checks.
Upgrade every binary that can see a post-quantum user, servers included,
before anyone rotates.
Publishing the classic three line key and holding the ML-KEM key
elsewhere would remove this constraint; it is an open item in
[TODO.filmil.md](../TODO.filmil.md).

A config may also set `requirepacking: eepq`.
The client then refuses to write a regular file under any other packing.
That catches a config whose `packing` line was changed.
It also refuses to read a regular file served with another packing,
through `Get`, `Open` and `upspinfs`.
That catches a directory server that offers an old **ee** version of a
file.
A `requirepacking` value that names no packing is an error, not an
absent requirement.
Directories, links, and Access and Group files are exempt, since access
control files must stay readable by everyone.
A user who sets it can no longer read their own **ee** data, so set it
only after the data that matters has been written again under **eepq**.

Data written under **ee** before the switch is not changed.
Treat it as exposed to a future quantum attacker if its directory entries
may have been captured.
Rewrapping it in place would not help, because the old ECDH wrapping may
already be in the attacker's hands.
A file that must be protected from now on has to be written again under
**eepq**, which gives it a fresh *dkey* and a fresh ciphertext.

The cost is directory entry size.
A wrapped key takes 161 bytes for a P-256 reader under **ee**.
Under **eepq** it takes 1251 bytes for a `p256+mlkem768` reader (the
1088 byte ML-KEM-768 ciphertext plus its length) and up to 1803 bytes
for a `p521+mlkem1024` reader.
An entry with one reader therefore grows from 263 to 1353 bytes, and each
further reader adds the wrapped key size.
The directory server stores and logs every entry, so a tree shared with
many readers grows by about eight times in its metadata.

To switch, generate a post-quantum key with
`upspin keygen -rotate -curve p256+mlkem768`, follow the rotation steps in
`upspin rotate -help`, and set `packing: eepq` in the config file.
A post-quantum key is generated from a 256 bit secret seed, written as 16
proquint words, twice the length of a classic seed.
FIPS 203 requires the ML-KEM seed to have at least the strength of the KEM.
A 128 bit seed would let a quantum attacker recover the whole key by
Grover search of the seed, at about 2^64 work, without attacking ML-KEM
at all.
Both halves of the key derive from the 256 bit seed, so the seed written
on paper still restores both.

The directory server needs to store its hierarchy of directory entries
somewhere.
(It is represented as a
[Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree), a tree of hash
values.)
The server uses the encryption scheme described above to store its data in the
storage server.


## Key representations

The original document says that form 3 of a key pair, the secret seed, is
128 bits of entropy expressed as proquints.
That holds for a classic key type.
A post-quantum key type such as `p256+mlkem768` uses 256 bits, written as
16 proquint words.
It also adds a fourth line to form 1, the string form, with the ML-KEM
encapsulation key, and a second line to the private key file with the
ML-KEM seed.
