// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
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

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	secretsharing "github.com/bytemare/secret-sharing"
)

// A Ciphersuite defines the elliptic curve group to use.
type Ciphersuite byte

const (
	// Ristretto255Sha512 identifies the Ristretto255 group and SHA-512.
	Ristretto255Sha512 = Ciphersuite(ecc.Ristretto255Sha512)

	// decaf448Shake256 identifies the Decaf448 group and Shake-256. Not supported.
	// decaf448Shake256 = 2.

	// P256Sha256 identifies the NIST P-256 group and SHA-256.
	P256Sha256 = Ciphersuite(ecc.P256Sha256)

	// P384Sha384 identifies the NIST P-384 group and SHA-384.
	P384Sha384 = Ciphersuite(ecc.P384Sha384)

	// P521Sha512 identifies the NIST P-512 group and SHA-512.
	P521Sha512 = Ciphersuite(ecc.P521Sha512)

	// Edwards25519Sha512 identifies the Edwards25519 group and SHA2-512.
	Edwards25519Sha512 = Ciphersuite(ecc.Edwards25519Sha512)

	// Secp256k1 identifies the SECp256k1 group and SHA-256.
	Secp256k1 = Ciphersuite(ecc.Secp256k1Sha256)
)

// Available returns whether the Ciphersuite is supported, useful to avoid casting to an unsupported group identifier.
func (c Ciphersuite) Available() bool {
	switch c {
	case Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512, Edwards25519Sha512, Secp256k1:
		return true
	default:
		return false
	}
}

// Group returns the elliptic curve group used in the ciphersuite.
func (c Ciphersuite) Group() ecc.Group {
	if !c.Available() {
		return 0
	}

	return ecc.Group(c)
}

func checkPolynomial(threshold uint16, p secretsharing.Polynomial) error {
	if len(p) != int(threshold) {
		return errPolynomialLength
	}

	if err := p.Verify(); err != nil {
		return fmt.Errorf("invalid polynomial: %w", err)
	}

	if p[0].IsZero() {
		return errInvalidPolynomialSecretZero
	}

	if threshold > 1 && p[threshold-1].IsZero() {
		return errInvalidPolynomialHighestDegreeZero
	}

	return nil
}

func checkCommitment(g ecc.Group, threshold uint16, commitment []*ecc.Element) error {
	if len(commitment) == 0 {
		return errCommitmentEmpty
	}

	if len(commitment) != int(threshold) {
		return errPolynomialLength
	}

	for _, coefficient := range commitment {
		if coefficient == nil {
			return errCommitmentNilElement
		}

		if !elementInGroup(coefficient, g) {
			return errCommitmentWrongGroup
		}
	}

	if commitment[0].IsIdentity() {
		return errCommitmentIdentityElement
	}

	if threshold > 1 && commitment[threshold-1].IsIdentity() {
		return errCommitmentIdentityElement
	}

	return nil
}

func elementInGroup(element *ecc.Element, group ecc.Group) bool {
	defer func() {
		_ = recover()
	}()

	if element == nil || !group.Available() {
		return false
	}

	return element.Group() == group
}

func elementGroup(element *ecc.Element) (group ecc.Group, ok bool) {
	defer func() {
		if recover() != nil {
			group = 0
			ok = false
		}
	}()

	if element == nil {
		return 0, false
	}

	return element.Group(), true
}

func scalarInGroup(scalar *ecc.Scalar, group ecc.Group) bool {
	defer func() {
		_ = recover()
	}()

	if scalar == nil || !group.Available() {
		return false
	}

	return scalar.Group() == group
}

func checkSecretShare(g ecc.Group, share *ecc.Scalar) error {
	if share == nil {
		return errSecretShareNil
	}

	if !scalarInGroup(share, g) {
		return errSecretShareWrongGroup
	}

	return nil
}

func checkCommitmentSet(g ecc.Group, commitments [][]*ecc.Element) error {
	if len(commitments) == 0 {
		return errMissingCommitment
	}

	if len(commitments[0]) == 0 {
		return errMissingCommitment
	}

	threshold := uint16(len(commitments[0]))
	if int(threshold) != len(commitments[0]) {
		return errPolynomialLength
	}

	for _, commitment := range commitments {
		if len(commitment) == 0 {
			return errMissingCommitment
		}

		if err := checkCommitment(g, threshold, commitment); err != nil {
			return err
		}
	}

	return nil
}

func checkAggregateCommitment(threshold uint16, commitment []*ecc.Element) error {
	if threshold > 1 && commitment[threshold-1].IsIdentity() {
		return errAggregateCommitmentHighestDegree
	}

	return nil
}

func randomPolynomialCoefficient(g ecc.Group, index, threshold uint16) *ecc.Scalar {
	for {
		coefficient := g.NewScalar().Random()
		if index != 0 && index != threshold-1 {
			return coefficient
		}

		if !coefficient.IsZero() {
			return coefficient
		}
	}
}

var errIDOutOfRange = errors.New("identifier is above authorized range")

func checkParticipantID(id, maxSigners uint16) error {
	if id == 0 {
		return errParticipantIDZero
	}

	if maxSigners != 0 && id > maxSigners {
		return fmt.Errorf("%w [1:%d]: %d", errIDOutOfRange, maxSigners, id)
	}

	return nil
}

// NewParticipant instantiates a new participant with identifier id. The identifier must be non-zero and unique among
// the set of participants. maxSigners and threshold must be non-zero, and threshold must be at most maxSigners.
//
// The same Participant instance must be used throughout the protocol execution, because it stores the validated
// intermediary values between Start, Continue, and Finalize. Optionally, the participant's secret polynomial can be
// provided to set its secret and commitment, which enables re-instantiating the same participant if the same polynomial
// is used. A provided polynomial must have exactly threshold coefficients, valid same-group scalar coefficients, a
// non-zero secret coefficient, and a non-zero highest-degree coefficient. Interior zero coefficients and repeated
// coefficient values are valid.
func (c Ciphersuite) NewParticipant(
	id uint16,
	threshold, maxSigners uint16,
	polynomial ...*ecc.Scalar,
) (*Participant, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	if maxSigners == 0 {
		return nil, errMaxSignersZero
	}

	if threshold == 0 {
		return nil, errThresholdZero
	}

	if threshold > maxSigners {
		return nil, errThresholdAboveMaxSigners
	}

	if err := checkParticipantID(id, maxSigners); err != nil {
		return nil, err
	}

	p := &Participant{
		Identifier: id,
		config: &config{
			maxSigners: maxSigners,
			threshold:  threshold,
			group:      ecc.Group(c),
		},
		secrets: &secrets{
			secretShare: nil,
			polynomial:  nil,
		},
		commitment:          nil,
		verifiedCommitments: nil,
		state:               participantStateInitialized,
	}

	if err := p.initPoly(polynomial...); err != nil {
		return nil, err
	}

	commitment, err := secretsharing.Commit(p.group, p.polynomial)
	if err != nil {
		return nil, fmt.Errorf("failed to commit participant polynomial: %w", err)
	}

	p.commitment = commitment

	return p, nil
}

func commitmentsFromRound1DataSet(g ecc.Group, r1DataSet []*Round1Data) ([][]*ecc.Element, error) {
	if len(r1DataSet) == 0 {
		return nil, errRound1DataElements
	}

	seen := make(map[uint16]struct{}, len(r1DataSet))
	commitments := make([][]*ecc.Element, 0, len(r1DataSet))

	for _, data := range r1DataSet {
		if data == nil {
			return nil, errRound1NilPackage
		}

		id := data.SenderIdentifier
		if err := checkParticipantID(id, 0); err != nil {
			return nil, err
		}

		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf(errWrapperWithID, errRound1DuplicateSender, id)
		}

		seen[id] = struct{}{}

		if len(data.Commitment) == 0 {
			return nil, errMissingCommitment
		}

		if data.ProofOfKnowledge == nil || data.ProofOfKnowledge.R == nil || data.ProofOfKnowledge.Z == nil {
			return nil, fmt.Errorf("%w: participant %d", errAbortInvalidSignature, id)
		}

		if !verifyZKProof(g, id, data.Commitment[0], data.ProofOfKnowledge) {
			return nil, fmt.Errorf("%w: participant %d", errAbortInvalidSignature, id)
		}

		commitments = append(commitments, data.Commitment)
	}

	if err := checkCommitmentSet(g, commitments); err != nil {
		return nil, err
	}

	return commitments, nil
}

// VerificationKeyFromRound1 returns the global public key, usable to verify signatures produced in a threshold scheme.
// It validates each Round 1 commitment and proof of knowledge, so it must be called before proofs are cleared.
func VerificationKeyFromRound1(c Ciphersuite, r1DataSet []*Round1Data) (*ecc.Element, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	g := ecc.Group(c)

	commitments, err := commitmentsFromRound1DataSet(g, r1DataSet)
	if err != nil {
		return nil, err
	}

	pubKey := g.NewElement()

	for _, commitment := range commitments {
		pubKey.Add(commitment[0])
	}

	return pubKey, nil
}

// VerificationKeyFromCommitments returns the threshold setup's group public key from participant commitments. It assumes
// those commitments came from an already validated DKG transcript or another trusted source, because it does not verify
// the Round 1 proofs of knowledge.
func VerificationKeyFromCommitments(c Ciphersuite, commitments [][]*ecc.Element) (*ecc.Element, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	g := ecc.Group(c)
	if err := checkCommitmentSet(g, commitments); err != nil {
		return nil, err
	}

	pubKey := g.NewElement()

	for _, com := range commitments {
		pubKey.Add(com[0])
	}

	return pubKey, nil
}

// ComputeParticipantPublicKey computes the verification share for participant id given the commitments of round 1.
func ComputeParticipantPublicKey(c Ciphersuite, id uint16, commitments [][]*ecc.Element) (*ecc.Element, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	if len(commitments) == 0 {
		return nil, errMissingCommitment
	}

	if err := checkParticipantID(id, 0); err != nil {
		return nil, err
	}

	g := ecc.Group(c)
	if err := checkCommitmentSet(g, commitments); err != nil {
		return nil, err
	}

	pk := g.NewElement().Identity()

	for _, commitment := range commitments {
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
func VerifyPublicKey(c Ciphersuite, id uint16, pubKey *ecc.Element, commitments [][]*ecc.Element) error {
	if !c.Available() {
		return errInvalidCiphersuite
	}

	if pubKey == nil {
		return errNilPubKey
	}

	if !elementInGroup(pubKey, ecc.Group(c)) {
		return errPubKeyWrongGroup
	}

	yi, err := ComputeParticipantPublicKey(c, id, commitments)
	if err != nil {
		return err
	}

	if !pubKey.Equal(yi) {
		return fmt.Errorf(
			"%w: want %q got %q",
			errVerificationShareFailed,
			yi.Hex(),
			pubKey.Hex(),
		)
	}

	return nil
}

// VSSCommitmentFromRegistry returns the aggregate commitment for a complete registry.
func VSSCommitmentFromRegistry(registry *keys.PublicKeyShareRegistry) []*ecc.Element {
	return registry.Commitment()
}

// VSSCommitmentsFromRegistry returns the aggregate commitment for a complete registry.
//
// Deprecated: use VSSCommitmentFromRegistry.
func VSSCommitmentsFromRegistry(registry *keys.PublicKeyShareRegistry) [][]*ecc.Element {
	commitment := VSSCommitmentFromRegistry(registry)
	if commitment == nil {
		return nil
	}

	return [][]*ecc.Element{commitment}
}
