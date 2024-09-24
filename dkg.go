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
	"errors"
	"fmt"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
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

// Group returns the elliptic curve group used in the ciphersuite.
func (c Ciphersuite) Group() group.Group {
	if !c.Available() {
		return 0
	}

	return group.Group(c)
}

func checkPolynomial(threshold uint16, p secretsharing.Polynomial) error {
	if len(p) != int(threshold) {
		return errPolynomialLength
	}

	if err := p.Verify(); err != nil {
		return fmt.Errorf("invalid polynomial: %w", err)
	}

	return nil
}

var errIDOutOfRange = errors.New("identifier is above authorized range")

// NewParticipant instantiates a new participant with identifier id. The identifier must be different from zero and
// unique among the set of participants. The same participant instance must be used throughout the protocol execution,
// to ensure the correct internal intermediary values are used. Optionally, the participant's secret polynomial can be
// provided to set its secret and commitment (also enabling re-instantiating the same participant if the same polynomial
// is used).
func (c Ciphersuite) NewParticipant(
	id uint16,
	threshold, maxSigners uint16,
	polynomial ...*group.Scalar,
) (*Participant, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	if id == 0 {
		return nil, errParticipantIDZero
	}

	if id > maxSigners {
		return nil, fmt.Errorf("%w [1:%d]: %d", errIDOutOfRange, maxSigners, id)
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
			polynomial:  nil,
		},
		commitment: nil,
	}

	if err := p.initPoly(polynomial...); err != nil {
		return nil, err
	}

	p.commitment = secretsharing.Commit(p.group, p.polynomial)

	return p, nil
}

// Participant represent a party in the Distributed Key Generation. Once the DKG completed, all values must be erased.
type Participant struct {
	*secrets
	*config
	commitment []*group.Element
	Identifier uint16
}

type config struct {
	maxSigners uint16
	threshold  uint16
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
	p.polynomial = secretsharing.NewPolynomial(p.threshold)

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

	p.secretShare = p.polynomial.Evaluate(p.group.NewScalar().SetUInt64(uint64(p.Identifier)))

	return nil
}

// Start returns a participant's output for the first round.
func (p *Participant) Start() *Round1Data {
	return p.StartWithRandom(nil)
}

// StartWithRandom returns a participant's output for the first round and allows setting the random input for the NIZK
// proof.
func (p *Participant) StartWithRandom(random *group.Scalar) *Round1Data {
	package1 := &Round1Data{
		Group:            p.group,
		SenderIdentifier: p.Identifier,
		Commitment:       p.commitment,
		ProofOfKnowledge: generateZKProof(p.group, p.Identifier, p.polynomial[0], p.commitment[0], random),
	}

	return package1
}

// Continue ingests the broadcast data from other peers and returns a map of dedicated Round2Data structures
// for each peer.
func (p *Participant) Continue(r1DataSet []*Round1Data) (map[uint16]*Round2Data, error) {
	// We accept the case where the input does not contain the package from the participant.
	if len(r1DataSet) != int(p.maxSigners) && len(r1DataSet) != int(p.maxSigners-1) {
		return nil, errRound1DataElements
	}

	r2data := make(map[uint16]*Round2Data, p.maxSigners-1)

	for _, data := range r1DataSet {
		if data == nil || data.SenderIdentifier == p.Identifier {
			continue
		}

		if len(data.Commitment) == 0 || data.Commitment[0] == nil {
			return nil, errCommitmentNilElement
		}

		peer := data.SenderIdentifier

		// round1, step 5
		if !verifyZKProof(p.group, peer, data.Commitment[0], data.ProofOfKnowledge) {
			return nil, fmt.Errorf(
				"%w: participant %v",
				errAbortInvalidSignature,
				peer,
			)
		}

		// round 2, step 1
		peerS := p.group.NewScalar().SetUInt64(uint64(peer))
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

func getCommitment(r1DataSet []*Round1Data, id uint16) ([]*group.Element, error) {
	for _, r1d := range r1DataSet {
		if r1d.SenderIdentifier == id {
			if len(r1d.Commitment) == 0 {
				return nil, fmt.Errorf(errWrapperWithID, errCommitmentEmpty, id)
			}

			return r1d.Commitment, nil
		}
	}

	return nil, fmt.Errorf(errWrapperWithID, errCommitmentNotFound, id)
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

func (p *Participant) verifyRound2Data(r1 []*Round1Data, r2 *Round2Data) (*group.Element, error) {
	if err := p.checkRound2DataHeader(r2); err != nil {
		return nil, err
	}

	// Find the commitment from that participant.
	com, err := getCommitment(r1, r2.SenderIdentifier)
	if err != nil {
		return nil, err
	}

	// Verify the secret share is valid with regard to the commitment.
	err = p.verifyCommitmentPublicKey(r2.SenderIdentifier, r2.SecretShare, com)
	if err != nil {
		return nil, err
	}

	return com[0], nil
}

// Finalize ingests the broadcast data from round 1 and the round 2 data destined for the participant,
// and returns the participant's secret share and verification key, and the group's public key.
func (p *Participant) Finalize(r1DataSet []*Round1Data, r2DataSet []*Round2Data) (*keys.KeyShare, error) {
	if len(r1DataSet) != int(p.maxSigners) && len(r1DataSet) != int(p.maxSigners-1) {
		return nil, errRound1DataElements
	}

	if len(r2DataSet) != int(p.maxSigners-1) {
		return nil, errRound2DataElements
	}

	secretKey := p.group.NewScalar()
	groupPublic := p.group.NewElement()

	for _, data := range r2DataSet {
		peerCommitment, err := p.verifyRound2Data(r1DataSet, data)
		if err != nil {
			return nil, err
		}

		secretKey.Add(data.SecretShare)
		groupPublic.Add(peerCommitment)
	}

	secretKey.Add(p.secretShare)
	p.secretShare.Zero()

	return &keys.KeyShare{
		Secret:         secretKey,
		GroupPublicKey: groupPublic.Add(p.commitment[0]),
		PublicKeyShare: keys.PublicKeyShare{
			PublicKey:     p.group.Base().Multiply(secretKey),
			VssCommitment: p.commitment,
			ID:            p.Identifier,
			Group:         p.group,
		},
	}, nil
}

func (p *Participant) verifyCommitmentPublicKey(id uint16, share *group.Scalar, commitment []*group.Element) error {
	pk := p.group.Base().Multiply(share)
	if !secretsharing.Verify(p.group, p.Identifier, pk, commitment) {
		return fmt.Errorf(
			"%w: %d",
			errAbortInvalidSecretShare,
			id,
		)
	}

	return nil
}

// GroupPublicKeyFromRound1 returns the global public key, usable to verify signatures produced in a threshold scheme.
func GroupPublicKeyFromRound1(c Ciphersuite, r1DataSet []*Round1Data) (*group.Element, error) {
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

// GroupPublicKeyFromCommitments returns the threshold's setup group public key, given all the commitments from all the
// participants.
func GroupPublicKeyFromCommitments(c Ciphersuite, commitments [][]*group.Element) (*group.Element, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	g := group.Group(c)
	pubKey := g.NewElement()

	for _, com := range commitments {
		pubKey.Add(com[0])
	}

	return pubKey, nil
}

// ComputeParticipantPublicKey computes the verification share for participant id given the commitments of round 1.
func ComputeParticipantPublicKey(c Ciphersuite, id uint16, commitments [][]*group.Element) (*group.Element, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	if len(commitments) == 0 {
		return nil, errMissingCommitment
	}

	g := group.Group(c)
	pk := g.NewElement().Identity()

	for _, commitment := range commitments {
		if len(commitment) == 0 {
			return nil, errMissingCommitment
		}

		prime, err := secretsharing.PubKeyForCommitment(g, id, commitment)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		pk.Add(prime)
	}

	return pk, nil
}

// VerifyPublicKey verifies if the pubKey associated to id is valid given the public VSS commitments of the other
// participants.
func VerifyPublicKey(c Ciphersuite, id uint16, pubKey *group.Element, commitments [][]*group.Element) error {
	if !c.Available() {
		return errInvalidCiphersuite
	}

	if pubKey == nil {
		return errNilPubKey
	}

	yi, err := ComputeParticipantPublicKey(c, id, commitments)
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

// VSSCommitmentsFromRegistry returns all the commitments for the set of PublicKeyShares in the registry.
func VSSCommitmentsFromRegistry(registry *keys.PublicKeyShareRegistry) [][]*group.Element {
	c := make([][]*group.Element, 0, len(registry.PublicKeyShares))

	for _, pks := range registry.PublicKeyShares {
		c = append(c, pks.VssCommitment)
	}

	return c
}
