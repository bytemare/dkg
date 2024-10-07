# Distributed Key Generation
[![dkg](https://github.com/bytemare/dkg/actions/workflows/code-scan.yml/badge.svg)](https://github.com/bytemare/dkg/actions/workflows/code-scan.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/dkg.svg)](https://pkg.go.dev/github.com/bytemare/dkg)
[![codecov](https://codecov.io/gh/bytemare/dkg/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/dkg)

```
  import "github.com/bytemare/dkg"
```

Package dkg provides an efficient distributed key generation system in Go, easy to use.
It builds on the 2-round Pederson DGK and extends it with zero-knowledge proofs to protect against rogue-key attacks of
Byzantine participants, as defined in [FROST](https://eprint.iacr.org/2020/852.pdf).
This is secure for any _t among n_ participants in a (t,n)-threshold scheme.

This effectively generates keys among participants without the need of a trusted dealer or third-party. These keys are
generally valid keys, and can be used in [FROST](https://github.com/bytemare/frost) and [OPRFs](https://github.com/bytemare/oprf).

#### References

- Pederson introduced the [first DKG protocol](https://link.springer.com/chapter/10.1007/3-540-46416-6_47), based on Feldman's Verifiable Secret Sharing.
- Komlo & Goldberg [add zero-knowledge proofs](https://eprint.iacr.org/2020/852.pdf) to the Ped-DKG.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/dkg.svg)](https://pkg.go.dev/github.com/bytemare/dkg)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/dkg).

## Usage

### Requirements

- All parties are identified with distinct ```uint16``` non-zero IDs.
- Communicate over confidential, authenticated, and secure channels.
- All participants honestly follow the protocol (they can, nevertheless, identify a misbehaving participant).

### Setup

Use the same ciphersuite for the DKG setup and the key usage in other protocol executions.

### Error handling

In case of an identified misbehaving participant, abort the protocol immediately. If this happens there might be a serious
problem that must be investigated. One may re-run the protocol after excluding that participant and solving the problem.

### Protocol

The following steps describe how to run the DKG among participants. Note that participants maintain a state between phases.
For each participant:
1. Run ```Init()```
    - this returns a round 1 package
    - send/broadcast this package to every other participant
      (this might include the very same participant, in which case it will discard it)
2. Collect all the round 1 packages from other participants
3. Run ```Continue()``` with the collection of round 1 packages
    - this returns round 2 packages, one destined to each other participant
    - each package specifies the intended receiver
    - send it to the intended receiver
4. Collect all round 2 packages destined to the participant
5. Run ```Finalize()``` with the collected round 1 and round 2 packages
    - returns the participant's own secret signing share,
      the corresponding verification/public share, and the group's public key
6. Erase all intermediary values received and computed by the participants (including in their states)
7. Optionally, compute the verification keys for each other participant and store them
8. You might want each participant to already send their ```PublicKeyShare``` to a central coordinator or broadcast it 
   to the other participants, as required to run the [FROST](https://github.com/bytemare/frost) protocol.

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/dkg/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
