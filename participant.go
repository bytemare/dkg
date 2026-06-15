// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg

import (
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	secretsharing "github.com/bytemare/secret-sharing"
)

const (
	participantStateInitialized participantState = iota
	participantStateStarted
	participantStateContinued
	participantStateFinalized
)

// Participant represents a party in the Distributed Key Generation. A Participant is stateful: Start, Continue, and
// Finalize are one-shot protocol phases on the same instance. Once the DKG is complete, all intermediary values must be
// erased.
type Participant struct {
	*secrets
	*config
	verifiedCommitments map[uint16][]*ecc.Element
	commitment          []*ecc.Element
	Identifier          uint16
	state               participantState
}

type participantState uint8

type config struct {
	maxSigners uint16
	threshold  uint16
	group      ecc.Group
}

type secrets struct {
	secretShare *ecc.Scalar
	polynomial  secretsharing.Polynomial
}

// Start returns a participant's output for the first round and advances the participant to the started state.
func (p *Participant) Start() (*Round1Data, error) {
	return p.StartWithRandom(nil)
}

// StartWithRandom returns a participant's output for the first round and allows setting the Schnorr proof nonce used
// by the NIZK proof. Omit random in normal use; it must stay secret and be unique for a given secret across distinct
// challenges, because reuse or disclosure can leak the secret.
func (p *Participant) StartWithRandom(random *ecc.Scalar) (*Round1Data, error) {
	if err := p.startable(); err != nil {
		return nil, err
	}

	if p.config == nil || p.secrets == nil || !p.group.Available() {
		return nil, errParticipantUninitialized
	}

	if err := checkParticipantID(p.Identifier, p.maxSigners); err != nil {
		return nil, err
	}

	if err := checkPolynomial(p.threshold, p.polynomial); err != nil {
		return nil, err
	}

	if err := checkCommitment(p.group, p.threshold, p.commitment); err != nil {
		return nil, err
	}

	if err := checkSecretShare(p.group, p.secretShare); err != nil {
		return nil, err
	}

	var (
		proof *Signature
		err   error
	)

	if random == nil {
		proof, err = generateZKProof(p.group, p.Identifier, p.polynomial[0], p.commitment[0])
	} else {
		proof, err = generateZKProof(p.group, p.Identifier, p.polynomial[0], p.commitment[0], random)
	}

	if err != nil {
		return nil, err
	}

	package1 := &Round1Data{
		Group:            p.group,
		SenderIdentifier: p.Identifier,
		Commitment:       copyCommitment(p.commitment),
		ProofOfKnowledge: proof,
	}

	p.state = participantStateStarted

	return package1, nil
}

// Continue ingests the broadcast data from other peers, verifies their proofs of knowledge, stores the verified
// commitments for Finalize, and returns one Round2Data package for each peer.
func (p *Participant) Continue(r1DataSet []*Round1Data) (map[uint16]*Round2Data, error) {
	if err := p.continueable(); err != nil {
		return nil, err
	}

	// We accept the case where the input does not contain the package from the participant.
	r1ByID, err := p.checkRound1DataSet(r1DataSet)
	if err != nil {
		return nil, err
	}

	r2data := make(map[uint16]*Round2Data, p.maxSigners-1)
	verifiedCommitments := make(map[uint16][]*ecc.Element, p.maxSigners)
	verifiedCommitments[p.Identifier] = copyCommitment(p.commitment)

	for i := 1; i <= int(p.maxSigners); i++ {
		peer := uint16(i)
		if peer == p.Identifier {
			continue
		}

		data := r1ByID[peer]
		if err = checkCommitment(p.group, p.threshold, data.Commitment); err != nil {
			return nil, err
		}

		// round1, step 5
		if !verifyZKProof(p.group, peer, data.Commitment[0], data.ProofOfKnowledge) {
			return nil, fmt.Errorf(
				"%w: participant %v",
				errAbortInvalidSignature,
				peer,
			)
		}

		verifiedCommitments[peer] = copyCommitment(data.Commitment)

		// round 2, step 1
		peerS := p.group.NewScalar().SetUInt64(uint64(peer))
		r2data[peer] = &Round2Data{
			Group:               p.group,
			SenderIdentifier:    p.Identifier,
			RecipientIdentifier: peer,
			SecretShare:         p.polynomial.Evaluate(peerS),
		}
	}

	p.verifiedCommitments = verifiedCommitments
	p.resetPolynomial()
	p.state = participantStateContinued

	return r2data, nil
}

// Finalize ingests the same round 1 commitments accepted by Continue and the round 2 data destined for the participant,
// then returns the participant's secret share, verification key, and the group's public key. Round 1 proofs may be
// cleared after Continue, but the commitments must still match the verified transcript.
func (p *Participant) Finalize(r1DataSet []*Round1Data, r2DataSet []*Round2Data) (*keys.KeyShare, error) {
	if err := p.finalizable(); err != nil {
		return nil, err
	}

	r1ByID, err := p.checkRound1DataSet(r1DataSet)
	if err != nil {
		return nil, err
	}

	r2ByID, err := p.checkRound2DataSet(r2DataSet)
	if err != nil {
		return nil, err
	}

	verifiedCommitments := p.verifiedCommitments
	if len(verifiedCommitments) == 0 {
		return nil, errParticipantUninitialized
	}

	for id, r1 := range r1ByID {
		verified, ok := verifiedCommitments[id]
		if !ok {
			return nil, fmt.Errorf("%w: %d", errCommitmentNotFound, id)
		}

		if !commitmentsEqual(r1.Commitment, verified) {
			return nil, fmt.Errorf("%w: %d", errRound1CommitmentMismatch, id)
		}
	}

	secretKey := p.group.NewScalar()
	commitment := copyCommitment(verifiedCommitments[p.Identifier])

	for i := 1; i <= int(p.maxSigners); i++ {
		peer := uint16(i)
		if peer == p.Identifier {
			continue
		}

		data := r2ByID[peer]

		var peerCommitment []*ecc.Element

		peerCommitment, err = p.verifyRound2Data(verifiedCommitments, data)
		if err != nil {
			return nil, err
		}

		secretKey.Add(data.SecretShare)

		for i, coefficient := range peerCommitment {
			commitment[i].Add(coefficient)
		}
	}

	if err = checkAggregateCommitment(p.threshold, commitment); err != nil {
		return nil, err
	}

	secretKey.Add(p.secretShare)

	share, err := keys.NewKeyShare(p.group, p.Identifier, secretKey, commitment[0], commitment)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeyShare: %w", err)
	}

	p.secretShare.Zero()
	p.state = participantStateFinalized

	return share, nil
}

func (p *Participant) resetPolynomial() {
	for _, s := range p.polynomial {
		s.Zero()
	}
}

func copyCommitment(commitment []*ecc.Element) []*ecc.Element {
	if commitment == nil {
		return nil
	}

	out := make([]*ecc.Element, len(commitment))
	for i, coefficient := range commitment {
		if coefficient != nil {
			out[i] = coefficient.Copy()
		}
	}

	return out
}

func commitmentsEqual(a, b []*ecc.Element) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] == nil || b[i] == nil {
			if a[i] != nil || b[i] != nil {
				return false
			}

			continue
		}

		group, ok := elementGroup(b[i])
		if !ok {
			return false
		}

		if !elementInGroup(a[i], group) {
			return false
		}

		if !a[i].Equal(b[i]) {
			return false
		}
	}

	return true
}

func (p *Participant) startable() error {
	if p == nil {
		return errParticipantUninitialized
	}

	switch p.state {
	case participantStateInitialized:
		return nil
	case participantStateStarted:
		return errParticipantAlreadyStarted
	case participantStateContinued:
		return errParticipantAlreadyContinued
	case participantStateFinalized:
		return errParticipantAlreadyFinalized
	default:
		return errParticipantUninitialized
	}
}

func (p *Participant) continueable() error {
	if p == nil {
		return errParticipantUninitialized
	}

	switch p.state {
	case participantStateInitialized:
		return errParticipantNotStarted
	case participantStateStarted:
		return nil
	case participantStateContinued:
		return errParticipantAlreadyContinued
	case participantStateFinalized:
		return errParticipantAlreadyFinalized
	default:
		return errParticipantUninitialized
	}
}

func (p *Participant) finalizable() error {
	if p == nil {
		return errParticipantUninitialized
	}

	switch p.state {
	case participantStateInitialized, participantStateStarted:
		return errParticipantNotContinued
	case participantStateContinued:
		return nil
	case participantStateFinalized:
		return errParticipantAlreadyFinalized
	default:
		return errParticipantUninitialized
	}
}

func (p *Participant) initPoly(polynomial ...*ecc.Scalar) error {
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
			p.polynomial[i] = randomPolynomialCoefficient(p.group, i, p.threshold)
		}
	}

	p.secretShare = p.polynomial.Evaluate(p.group.NewScalar().SetUInt64(uint64(p.Identifier)))

	return nil
}

func (p *Participant) checkRound1DataSet(r1DataSet []*Round1Data) (map[uint16]*Round1Data, error) {
	if len(r1DataSet) != int(p.maxSigners) && len(r1DataSet) != int(p.maxSigners-1) {
		return nil, errRound1DataElements
	}

	seen := make(map[uint16]struct{}, len(r1DataSet))
	round1ByID := make(map[uint16]*Round1Data, len(r1DataSet))

	for _, data := range r1DataSet {
		if data == nil {
			return nil, errRound1NilPackage
		}

		id := data.SenderIdentifier
		if err := checkParticipantID(id, p.maxSigners); err != nil {
			return nil, err
		}

		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf(errWrapperWithID, errRound1DuplicateSender, id)
		}

		seen[id] = struct{}{}

		round1ByID[id] = data
	}

	for i := 1; i <= int(p.maxSigners); i++ {
		id := uint16(i)
		if id == p.Identifier {
			continue
		}

		if round1ByID[id] == nil {
			return nil, fmt.Errorf(errWrapperWithID, errRound1MissingPackage, id)
		}
	}

	return round1ByID, nil
}

func (p *Participant) verifyCommitmentPublicKey(id uint16, share *ecc.Scalar, commitment []*ecc.Element) error {
	if err := checkSecretShare(p.group, share); err != nil {
		return fmt.Errorf(errWrapperWithID, err, id)
	}

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

func getVerifiedCommitment(commitments map[uint16][]*ecc.Element, id uint16) ([]*ecc.Element, error) {
	com := commitments[id]
	if len(com) == 0 {
		return nil, fmt.Errorf(errWrapperWithID, errCommitmentNotFound, id)
	}

	return com, nil
}

func (p *Participant) checkRound2DataHeader(d *Round2Data) error {
	if d == nil {
		return errRound2NilPackage
	}

	if err := checkParticipantID(d.SenderIdentifier, p.maxSigners); err != nil {
		return err
	}

	if err := checkParticipantID(d.RecipientIdentifier, p.maxSigners); err != nil {
		return err
	}

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

func (p *Participant) checkRound2DataSet(r2DataSet []*Round2Data) (map[uint16]*Round2Data, error) {
	if len(r2DataSet) != int(p.maxSigners-1) {
		return nil, errRound2DataElements
	}

	peers := make(map[uint16]*Round2Data, p.maxSigners-1)
	for _, data := range r2DataSet {
		if err := p.checkRound2DataHeader(data); err != nil {
			return nil, err
		}

		if _, ok := peers[data.SenderIdentifier]; ok {
			return nil, fmt.Errorf(errWrapperWithID, errRound2DuplicateSender, data.SenderIdentifier)
		}

		if err := checkSecretShare(p.group, data.SecretShare); err != nil {
			return nil, fmt.Errorf(errWrapperWithID, err, data.SenderIdentifier)
		}

		peers[data.SenderIdentifier] = data
	}

	for i := 1; i <= int(p.maxSigners); i++ {
		id := uint16(i)
		if id == p.Identifier {
			continue
		}

		if peers[id] == nil {
			return nil, fmt.Errorf(errWrapperWithID, errRound2MissingPackage, id)
		}
	}

	return peers, nil
}

func (p *Participant) verifyRound2Data(r1 map[uint16][]*ecc.Element, r2 *Round2Data) ([]*ecc.Element, error) {
	if err := p.checkRound2DataHeader(r2); err != nil {
		return nil, err
	}

	// Find the commitment from that participant.
	com, err := getVerifiedCommitment(r1, r2.SenderIdentifier)
	if err != nil {
		return nil, err
	}

	if err = checkCommitment(p.group, p.threshold, com); err != nil {
		return nil, fmt.Errorf(errWrapperWithID, err, r2.SenderIdentifier)
	}

	// Verify the secret share is valid with regard to the commitment.
	err = p.verifyCommitmentPublicKey(r2.SenderIdentifier, r2.SecretShare, com)
	if err != nil {
		return nil, err
	}

	return com, nil
}
