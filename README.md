# Distributed Key Generation
[![dkg](https://github.com/bytemare/dkg/actions/workflows/wf-analysis.yml/badge.svg)](https://github.com/bytemare/dkg/actions/workflows/wf-analysis.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/dkg.svg)](https://pkg.go.dev/github.com/bytemare/dkg)
[![codecov](https://codecov.io/gh/bytemare/dkg/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/dkg)

```go
  import "github.com/bytemare/dkg"
```

Package dkg provides an efficient distributed key generation system in Go, easy to use.
It builds on the 2-round Pedersen DKG and extends it with zero-knowledge proofs to protect against rogue-key attacks of
Byzantine participants, as defined in [FROST](https://eprint.iacr.org/2020/852.pdf).
This is secure for any _t among n_ participants in a (t,n)-threshold scheme.

This effectively generates keys among participants without the need of a trusted dealer or third-party. These keys are
generally valid keys, and can be used in [FROST](https://github.com/bytemare/frost) and [OPRFs](https://github.com/bytemare/oprf).

References:

- Pedersen introduced the [first DKG protocol](https://link.springer.com/chapter/10.1007/3-540-46416-6_47), based on Feldman's Verifiable Secret Sharing.
- Komlo & Goldberg [add zero-knowledge proofs](https://eprint.iacr.org/2020/852.pdf) to the Ped-DKG.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/dkg.svg)](https://pkg.go.dev/github.com/bytemare/dkg)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/dkg).

## Usage

### Requirements

- All parties are identified with distinct ```uint16``` non-zero IDs in the range ```[1:maxSigners]```.
- ```threshold``` and ```maxSigners``` must be non-zero, and ```threshold``` must be at most ```maxSigners```.
- Communicate over confidential, authenticated, and secure channels.
- All participants honestly follow the protocol (they can, nevertheless, identify a misbehaving participant).

### Setup

Use the same ciphersuite for the DKG setup and the key usage in other protocol executions.

### Error handling

In case of an identified misbehaving participant, abort the protocol immediately. If this happens there might be a serious
problem that must be investigated. One may re-run the protocol after excluding that participant and solving the problem.

### Protocol

The following steps describe how to run the DKG among participants. Participants maintain state between phases:
```Start()```, ```Continue()```, and ```Finalize()``` are one-shot state transitions on the same ```Participant```
instance. Failed calls do not advance state and can be retried with corrected input.
For each participant:
1. Create the participant with ```NewParticipant(id, threshold, maxSigners)```.
2. Run ```Start()```
    - this returns a round 1 package
    - send/broadcast this package to every other participant
      (this might include the very same participant, in which case it will discard it)
3. Collect all the round 1 packages from other participants
4. Run ```Continue()``` with the collection of round 1 packages
    - this verifies the round 1 proofs of knowledge and stores the verified commitments
    - this returns round 2 packages, one destined to each other participant
    - each package specifies the intended receiver
    - Round2Data contains secret shares; send it only to the intended receiver over an authenticated confidential transport and never broadcast or log it
5. Collect all round 2 packages destined to the participant
6. Run ```Finalize()``` with the collected round 1 and round 2 packages
    - provide the same round-1 commitments accepted by ```Continue()```; proofs may be cleared after ```Continue()```
    - returns the participant's own secret signing share,
      the corresponding verification/public share, and the group's public key
7. Optionally compute the group verification key from round 1 with ```VerificationKeyFromRound1()``` before clearing
   round-1 proofs. After proofs are cleared, use already validated commitments or finalized public key shares.
8. Erase all intermediary values received and computed by the participants (including in their states)
9. You might want each participant to already send their ```PublicKeyShare``` to a central coordinator or broadcast it
   to the other participants, as required to run the [FROST](https://github.com/bytemare/frost) protocol.

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/dkg/tags).

## Release Integrity (SLSA Level 3)
Releases are built with the reusable [bytemare/slsa](https://github.com/bytemare/slsa) workflow and ship the evidence required for SLSA Level 3 compliance:

- 📦 Artifacts are uploaded to the release page, and include the deterministic source archive plus subjects.sha256, signed SBOM (sbom.cdx.json), GitHub provenance (*.intoto.jsonl), a reproducibility report (verification.json), and a signed Verification Summary Attestation (verification-summary.attestation.json[.bundle]).
- ✍️ All artifacts are signed using [Sigstore](https://sigstore.dev) with transparency via [Rekor](https://rekor.sigstore.dev).
- ✅ Verification (or see the latest docs at [bytemare/slsa](https://github.com/bytemare/slsa)):
```shell
curl -sSL https://raw.githubusercontent.com/bytemare/slsa/main/verify-release.sh -o verify-release.sh
chmod +x verify-release.sh
./verify-release.sh --repo <owner>/<repo> --tag <tag> --mode full --signer-repo bytemare/slsa
```
Run again with `--mode reproduce` to build in a container, or `--mode vsa` to validate just the verification summary.

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
