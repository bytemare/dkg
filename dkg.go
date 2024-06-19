// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package dkg implements the Distributed Key Generation described in FROST,
// using zero-knowledge proofs in Schnorr signatures.
package dkg

import (
	"fmt"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"
)

// A Ciphersuite defines the elliptic curve group to use.
type Ciphersuite byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group and SHA-512.
	Ristretto255Sha512 = Ciphersuite(group.Ristretto255Sha512)

	// decaf448Shake256 identifies the Decaf448 group and Shake-256. Not supported.
	// decaf448Shake256 = 2.

	// P256Sha256 identifies the NIST P-256 group and SHA-256.
	P256Sha256 = Ciphersuite(group.P256Sha256)

	// P384Sha384 identifies the NIST P-384 group and SHA-384.
	P384Sha384 = Ciphersuite(group.P384Sha384)

	// P521Sha512 identifies the NIST P-512 group and SHA-512.
	P521Sha512 = Ciphersuite(group.P521Sha512)

	// Edwards25519Sha512 identifies the Edwards25519 group and SHA2-512.
	Edwards25519Sha512 = Ciphersuite(group.Edwards25519Sha512)

	// Secp256k1 identifies the SECp256k1 group and SHA-256.
	Secp256k1 = Ciphersuite(group.Secp256k1)
)

// Available returns whether the Ciphersuite is supported, useful to avoid casting to an unsupported group.
func (c Ciphersuite) Available() bool {
	switch c {
	case Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512, Edwards25519Sha512, Secp256k1:
		return true
	default:
		return false
	}
}

// KeyShare identifies the sharded key share for a given participant.
type KeyShare struct {
	// The SecretKey of a participant (or secret share).
	SecretKey *group.Scalar

	// The PublicKey of SecretKey belonging to the participant.
	PublicKey *group.Element

	// Identifier of the participant.
	Identifier uint64
}

func checkPolynomial(threshold uint, p secretsharing.Polynomial) error {
	if uint(len(p)) != threshold {
		return errPolynomialLength
	}

	if err := p.Verify(); err != nil {
		return fmt.Errorf("invalid polynomial: %w", err)
	}

	return nil
}

// NewParticipant instantiates a new participant with identifier id. The identifier must be different from zero and
// unique among the set of participants. The same participant instance must be used throughout the protocol execution,
// to ensure the correct internal intermediary values are used. Optionally, the participant's secret polynomial can be
// provided to set its secret and commitment (also enabling re-instantiating the same participant if the same polynomial
// is used).
func (c Ciphersuite) NewParticipant(
	id uint64,
	maxSigners, threshold uint,
	polynomial ...*group.Scalar,
) (*Participant, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	if id == 0 {
		return nil, errParticipantIDZero
	}

	p := &Participant{
		Identifier: id,
		config: &config{
			maxSigners: maxSigners,
			threshold:  threshold,
			group:      group.Group(c),
		},
		secrets: &secrets{
			secretShare: nil,
			polynomial:  secretsharing.NewPolynomial(threshold),
		},
		publicShare: nil,
	}

	if err := p.initPoly(polynomial...); err != nil {
		return nil, err
	}

	return p, nil
}

// Participant represent a party in the Distributed Key Generation. Once the DKG completed, all values must be erased.
type Participant struct {
	publicShare *group.Element
	*secrets
	*config
	Identifier uint64
}

type config struct {
	maxSigners uint
	threshold  uint
	group      group.Group
}

type secrets struct {
	secretShare *group.Scalar
	polynomial  secretsharing.Polynomial
}

func (p *Participant) resetPolynomial() {
	for _, s := range p.polynomial {
		s.Zero()
	}
}

func (p *Participant) initPoly(polynomial ...*group.Scalar) error {
	if len(polynomial) != 0 {
		if err := checkPolynomial(p.threshold, polynomial); err != nil {
			return err
		}

		for i, poly := range polynomial {
			p.polynomial[i] = poly.Copy()
		}
	} else {
		for i := range p.threshold {
			p.polynomial[i] = p.group.NewScalar().Random()
		}
	}

	p.secretShare = p.polynomial.Evaluate(p.group.NewScalar().SetUInt64(p.Identifier))

	return nil
}

// Start returns a participant's output for the first round.
func (p *Participant) Start() *Round1Data {
	return p.StartWithRandom(nil)
}

// StartWithRandom returns a participant's output for the first round and allows setting the random input for the NIZK
// proof.
func (p *Participant) StartWithRandom(random *group.Scalar) *Round1Data {
	commitment := secretsharing.Commit(p.group, p.polynomial)
	p.publicShare = commitment[0]
	package1 := &Round1Data{
		threshold:        p.threshold,
		Group:            p.group,
		SenderIdentifier: p.Identifier,
		Commitment:       commitment,
		ProofOfKnowledge: generateZKProof(p.group, p.Identifier, p.polynomial[0], commitment[0], random),
	}

	return package1
}

// Continue ingests the broadcast data from other peers and returns a map of dedicated Round2Data structures
// for each peer.
func (p *Participant) Continue(r1DataSet []*Round1Data) (map[uint64]*Round2Data, error) {
	// We consider the case where the input does not contain the package from the participant.
	if uint(len(r1DataSet)) != p.maxSigners && uint(len(r1DataSet)) != p.maxSigners-1 {
		return nil, errRound1DataElements
	}

	r2data := make(map[uint64]*Round2Data, p.maxSigners-1)

	for _, data := range r1DataSet {
		if data == nil || data.SenderIdentifier == p.Identifier {
			continue
		}

		if data.Commitment[0] == nil {
			return nil, errCommitmentNilElement
		}

		peer := data.SenderIdentifier

		// round1, step 5
		if !verifyZKProof(p.group, peer, data.Commitment[0], data.ProofOfKnowledge) {
			return nil, fmt.Errorf(
				"%w: participant %v",
				errInvalidSignature,
				peer,
			)
		}

		// round 2, step 1
		peerS := p.group.NewScalar().SetUInt64(peer)
		r2data[peer] = &Round2Data{
			Group:               p.group,
			SenderIdentifier:    p.Identifier,
			RecipientIdentifier: peer,
			SecretShare:         p.polynomial.Evaluate(peerS),
		}
	}

	p.resetPolynomial()

	return r2data, nil
}

func getCommitment(r1DataSet []*Round1Data, id uint64) (secretsharing.Commitment, error) {
	for _, r1d := range r1DataSet {
		if r1d.SenderIdentifier == id {
			if len(r1d.Commitment) == 0 {
				return nil, fmt.Errorf("%w: %d", errCommitmentEmpty, id)
			}

			return r1d.Commitment, nil
		}
	}

	return nil, fmt.Errorf("%w: %d", errCommitmentNotFound, id)
}

func (p *Participant) checkRound2DataHeader(d *Round2Data) error {
	if d.RecipientIdentifier == d.SenderIdentifier {
		return errRound2FaultyPackage
	}

	if d.SenderIdentifier == p.Identifier {
		return errRound2OwnPackage
	}

	if d.RecipientIdentifier != p.Identifier {
		return errRound2InvalidReceiver
	}

	return nil
}

// Finalize ingests the broadcast data from round 1 and the round 2 data destined for the participant,
// and returns the participant's secret share and verification key, and the group's public key.
func (p *Participant) Finalize(r1DataSet []*Round1Data, r2DataSet []*Round2Data) (*KeyShare, *group.Element, error) {
	if uint(len(r1DataSet)) != p.maxSigners && uint(len(r1DataSet)) != p.maxSigners-1 {
		return nil, nil, errRound1DataElements
	}

	if uint(len(r2DataSet)) != p.maxSigners-1 {
		return nil, nil, errRound2DataElements
	}

	secretKey := p.group.NewScalar()
	groupPublic := p.group.NewElement()
	ids := p.group.NewScalar().SetUInt64(p.Identifier)

	for _, data := range r2DataSet {
		if err := p.checkRound2DataHeader(data); err != nil {
			return nil, nil, err
		}

		// Find the commitment from that participant.
		com, err := getCommitment(r1DataSet, data.SenderIdentifier)
		if err != nil {
			return nil, nil, err
		}

		// Verify the secret share is valid with regard to the commitment.
		if _err := p.verifyCommitmentPublicKey(data.SenderIdentifier, data.SecretShare, ids, com); _err != nil {
			return nil, nil, _err
		}

		secretKey.Add(data.SecretShare)
		groupPublic.Add(com[0])
	}

	secretKey.Add(p.secretShare)
	groupPublic.Add(p.publicShare)
	p.secretShare.Zero()
	publicKey := p.group.Base().Multiply(secretKey)

	return &KeyShare{
		Identifier: p.Identifier,
		SecretKey:  secretKey,
		PublicKey:  publicKey,
	}, groupPublic, nil
}

func (p *Participant) verifyCommitmentPublicKey(id uint64, share, ids *group.Scalar, com []*group.Element) error {
	pk := p.group.Base().Multiply(share)

	pkc, err := PubKeyForCommitment(p.group, com, p.Identifier, ids)
	if err != nil {
		return fmt.Errorf(
			"%w: %d",
			err,
			id,
		)
	}

	if pk.Equal(pkc) != 1 {
		return fmt.Errorf(
			"%w: %d",
			errInvalidSecretShare,
			id,
		)
	}

	return nil
}

// GroupPublicKey returns the global public key, usable to verify signatures produced in a threshold scheme.
func GroupPublicKey(c Ciphersuite, r1DataSet []*Round1Data) (*group.Element, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	g := group.Group(c)
	pubKey := g.NewElement()

	for _, d := range r1DataSet {
		pubKey.Add(d.Commitment[0])
	}

	return pubKey, nil
}

// VerifyPublicKey verifies if the pubKey associated to id is valid given the public commitments in the data from the
// first round.
func VerifyPublicKey(c Ciphersuite, id uint64, pubKey *group.Element, r1data []*Round1Data) error {
	if !c.Available() {
		return errInvalidCiphersuite
	}

	if pubKey == nil {
		return errNilPubKey
	}

	yi, err := ComputeParticipantPublicKey(c, id, r1data)
	if err != nil {
		return err
	}

	if pubKey.Equal(yi) != 1 {
		return fmt.Errorf("%w: want %q got %q",
			errVerificationShareFailed,
			yi.Hex(),
			pubKey.Hex(),
		)
	}

	return nil
}

func comPubKey(g group.Group, s *group.Scalar, pk *group.Element, commitment []*group.Element) (*group.Element, error) {
	// if there are elements left and since j == 1, we can spare one exponentiation
	if commitment[1] == nil {
		return nil, errCommitmentNilElement
	}

	pk.Add(commitment[1].Copy().Multiply(s))

	i := 2
	j := uint64(1)

	js := g.NewScalar()

	for _, com := range commitment[i:] {
		if com == nil {
			return nil, errCommitmentNilElement
		}

		j++
		js.SetUInt64(j)
		pk.Add(com.Copy().Multiply(s.Copy().Pow(js)))
	}

	return pk, nil
}

// PubKeyForCommitment computes the public key corresponding to the commitment of participant id. ids is the scalar form
// of id, which is set appropriately if not already provided.
func PubKeyForCommitment(
	g group.Group,
	commitment []*group.Element,
	id uint64,
	ids ...*group.Scalar,
) (*group.Element, error) {
	if !Ciphersuite(g).Available() {
		return nil, errInvalidCiphersuite
	}

	var s *group.Scalar
	if len(ids) == 0 || ids[0] == nil {
		s = g.NewScalar().SetUInt64(id)
	} else {
		s = ids[0]
	}

	pk := commitment[0].Copy()

	switch {
	// If id == 1 we can spare exponentiation and multiplications
	case id == 1:
		for _, com := range commitment[1:] {
			if com == nil {
				return nil, errCommitmentNilElement
			}

			pk.Add(com)
		}
	case len(commitment) >= 2:
		return comPubKey(g, s, pk, commitment)
	}

	return pk, nil
}

// ComputeParticipantPublicKey computes the verification share for participant id given the commitments of round 1.
func ComputeParticipantPublicKey(c Ciphersuite, id uint64, r1data []*Round1Data) (*group.Element, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	if len(r1data) == 0 {
		return nil, errMissingRound1Data
	}

	g := group.Group(c)
	yi := g.NewElement().Identity()
	idS := g.NewScalar().SetUInt64(id)

	for _, p := range r1data {
		if p == nil {
			return nil, errMissingPackageRound1
		}

		if len(p.Commitment) == 0 {
			return nil, errNoCommitment
		}

		prime, err := PubKeyForCommitment(g, p.Commitment, id, idS)
		if err != nil {
			return nil, err
		}

		yi.Add(prime)
	}

	return yi, nil
}
