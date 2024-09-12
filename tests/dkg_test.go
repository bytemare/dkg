// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/dkg"
)

// TestCompleteDKG verifies
//   - execution of the protocol with a number of participants and threshold, and no errors.
//   - the correctness of each verification share.
//   - the correctness of the group public key.
//   - the correctness of the secret key recovery with regard to the public key.
func TestCompleteDKG(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		// valid r1DataSet set with and without own package
		p := c.makeParticipants(t)
		r1 := make([]*dkg.Round1Data, c.maxParticipants)

		// Step 1: Start and assemble packages.
		for i := range c.maxParticipants {
			r1[i] = p[i].Start()
		}

		// Step 2: Continue and assemble + triage packages.
		r2 := c.runRound2(t, p, r1)

		// Step 3: Clean the proofs.
		// This must be called by each participant on their copy of the r1DataSet.
		for _, d := range r1 {
			d.ProofOfKnowledge.Clear()
		}

		// Step 4: Finalize and test outputs.
		quals := []uint16{1, 3, 5}
		keyShares := make([]*dkg.KeyShare, 0, len(quals))
		registry := c.ciphersuite.NewPublicKeyShareRegistry(c.threshold, c.maxParticipants)
		pubKey, _ := dkg.GroupPublicKeyFromRound1(c.ciphersuite, r1)
		for _, participant := range p {
			keyShare, err := participant.Finalize(r1, r2[participant.Identifier])
			if err != nil {
				t.Fatal(err)
			}

			if keyShare.GroupPublicKey.Equal(pubKey) != 1 {
				t.Fatalf("expected same public key")
			}

			if keyShare.PublicKey.Equal(c.group.Base().Multiply(keyShare.Secret)) != 1 {
				t.Fatal("expected equality")
			}

			if err := registry.Add(keyShare.Public()); err != nil {
				t.Fatal(err)
			}

			// Assemble a subset to test key recovery.
			if slices.Contains(quals, participant.Identifier) { // only take the selected identifiers
				keyShares = append(keyShares, keyShare)
			}
		}

		{
			commitments := registry.Commitments()
			for _, k := range keyShares {
				if err := dkg.VerifyPublicKey(c.ciphersuite, k.Identifier(), k.PublicKey, commitments); err != nil {
					t.Fatal(err)
				}
			}
		}

		// Verify the threshold scheme by combining a subset of the shares.
		{
			combinedKeyShares := make([]secretsharing.Share, 0, len(quals))
			for _, k := range keyShares {
				combinedKeyShares = append(combinedKeyShares, k)
			}
			secret, err := secretsharing.CombineShares(c.group, combinedKeyShares)
			if err != nil {
				t.Fatal(err)
			}

			pk := c.group.Base().Multiply(secret)
			if pk.Equal(pubKey) != 1 {
				t.Fatal("expected recovered secret to be compatible with public key")
			}
		}
	})
}

func (c *testCase) makeParticipants(t *testing.T) []*dkg.Participant {
	ps := make([]*dkg.Participant, 0, c.maxParticipants)
	for i := range c.maxParticipants {
		p, err := c.ciphersuite.NewParticipant(i+1, c.threshold, c.maxParticipants)
		if err != nil {
			t.Fatal(err)
		}

		ps = append(ps, p)
	}

	return ps
}

func (c *testCase) runRound1(p []*dkg.Participant) []*dkg.Round1Data {
	r1 := make([]*dkg.Round1Data, 0, c.maxParticipants)
	for i := range c.maxParticipants {
		r1 = append(r1, p[i].Start())
	}

	return r1
}

func (c *testCase) runRound2(t *testing.T, p []*dkg.Participant, r1 []*dkg.Round1Data) map[uint16][]*dkg.Round2Data {
	r2 := make(map[uint16][]*dkg.Round2Data, c.maxParticipants)
	for i := range c.maxParticipants {
		r, err := p[i].Continue(r1)
		if err != nil {
			t.Fatal(err)
		}

		for id, data := range r {
			if r2[id] == nil {
				r2[id] = make([]*dkg.Round2Data, 0, c.maxParticipants-1)
			}
			r2[id] = append(r2[id], data)
		}
	}

	return r2
}

func (c *testCase) finalize(
	t *testing.T,
	participants []*dkg.Participant,
	r1 []*dkg.Round1Data,
	r2 map[uint16][]*dkg.Round2Data,
) []*dkg.KeyShare {
	keyShares := make([]*dkg.KeyShare, 0, c.maxParticipants)
	for _, participant := range participants {
		ks, err := participant.Finalize(r1, r2[participant.Identifier])
		if err != nil {
			t.Fatal(err)
		}

		keyShares = append(keyShares, ks)
	}

	return keyShares
}

func makeRegistry(t *testing.T, c *testCase, keyShares []*dkg.KeyShare) *dkg.PublicKeyShareRegistry {
	registry := c.ciphersuite.NewPublicKeyShareRegistry(c.threshold, c.maxParticipants)
	for _, keyShare := range keyShares {
		if err := registry.Add(keyShare.Public()); err != nil {
			t.Fatal(err)
		}
	}

	var err error
	registry.GroupPublicKey, err = dkg.GroupPublicKeyFromCommitments(c.ciphersuite, registry.Commitments())
	if err != nil {
		t.Fatal(err)
	}

	return registry
}

func completeDKG(
	t *testing.T,
	c *testCase,
) ([]*dkg.Participant, []*dkg.Round1Data, map[uint16][]*dkg.Round2Data, []*dkg.KeyShare, *dkg.PublicKeyShareRegistry) {
	p := c.makeParticipants(t)
	r1 := c.runRound1(p)
	r2 := c.runRound2(t, p, r1)
	keyShares := c.finalize(t, p, r1, r2)
	registry := makeRegistry(t, c, keyShares)

	return p, r1, r2, keyShares, registry
}

func TestCiphersuite_Available(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		if !c.ciphersuite.Available() {
			t.Fatal(errExpectedAvailability)
		}
	})
}

func TestCiphersuite_Group(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		if group.Group(c.ciphersuite) != c.group {
			t.Fatal(errUnexpectedCiphersuiteGroup)
		}

		if c.ciphersuite.Group() != group.Group(c.ciphersuite) {
			t.Fatal(errUnexpectedCiphersuiteGroup)
		}
	})

	t.Run("Bad group", func(t *testing.T) {
		if dkg.Ciphersuite(2).Group() != 0 {
			t.Fatal(errUnexpectedCiphersuiteGroup)
		}
	})
}

func TestCiphersuite_BadID(t *testing.T) {
	c := dkg.Ciphersuite(0)
	if c.Available() {
		t.Fatal(errUnexpectedAvailability)
	}

	c = dkg.Ciphersuite(2)
	if c.Available() {
		t.Fatal(errUnexpectedAvailability)
	}

	c = dkg.Ciphersuite(8)
	if c.Available() {
		t.Fatal(errUnexpectedAvailability)
	}
}

func testMakePolynomial(g group.Group, n uint16) secretsharing.Polynomial {
	p := secretsharing.NewPolynomial(n)
	for i := range n {
		p[i] = g.NewScalar().Random()
	}

	return p
}

func TestCiphersuite_NewParticipant(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants); err != nil {
			t.Fatal(err)
		}

		poly := testMakePolynomial(c.group, c.threshold)
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_Ciphersuite(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")

	testAllCases(t, func(c *testCase) {
		// Bad ciphersuite
		if _, err := dkg.Ciphersuite(0).NewParticipant(1, c.threshold, c.maxParticipants); err == nil ||
			err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error on invalid ciphersuite, want %q got %q", errInvalidCiphersuite, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_ParticipantIDZero(t *testing.T) {
	errParticipantIDZero := errors.New("identifier is 0")

	testAllCases(t, func(c *testCase) {
		if _, err := c.ciphersuite.NewParticipant(0, c.threshold, c.maxParticipants); err == nil ||
			err.Error() != errParticipantIDZero.Error() {
			t.Fatalf("expected error on id == 0, want %q got %q", errParticipantIDZero, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_ParticipantIDTooHigh(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		id := c.maxParticipants + 1
		errParticipantIDZero := fmt.Errorf("identifier %d is above authorized range [1:%d]", id, c.maxParticipants)
		if _, err := c.ciphersuite.NewParticipant(id, c.threshold, c.maxParticipants); err == nil ||
			err.Error() != errParticipantIDZero.Error() {
			t.Fatalf("expected error on id == 0, want %q got %q", errParticipantIDZero, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_PolynomialLength(t *testing.T) {
	errPolynomialLength := errors.New("invalid polynomial length")

	testAllCases(t, func(c *testCase) {
		poly := make([]*group.Scalar, c.threshold-1)
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}

		poly = make([]*group.Scalar, c.threshold+1)
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_PolyHasNilCoeff(t *testing.T) {
	errPolyHasNilCoeff := errors.New("invalid polynomial: the polynomial has a nil coefficient")

	testAllCases(t, func(c *testCase) {
		poly := make([]*group.Scalar, c.threshold)
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolyHasNilCoeff.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasNilCoeff, err)
		}

		poly = testMakePolynomial(c.group, c.threshold)
		poly[1] = nil
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolyHasNilCoeff.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasNilCoeff, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_PolyHasZeroCoeff(t *testing.T) {
	errPolyHasZeroCoeff := errors.New("invalid polynomial: one of the polynomial's coefficients is zero")

	testAllCases(t, func(c *testCase) {
		poly := testMakePolynomial(c.group, c.threshold)
		poly[1].Zero()
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolyHasZeroCoeff.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasZeroCoeff, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_PolyHasDuplicates(t *testing.T) {
	errPolyHasDuplicates := errors.New("invalid polynomial: the polynomial has duplicate coefficients")

	testAllCases(t, func(c *testCase) {
		poly := testMakePolynomial(c.group, c.threshold)
		poly[1].Set(poly[2])
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolyHasDuplicates.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasDuplicates, err)
		}
	})
}

func TestParticipant_Continue(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		// valid r1DataSet set with and without own package
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)

		if _, err := p[0].Continue(r1); err != nil {
			t.Fatal(err)
		}

		// valid r1dataset set without own package
		if _, err := p[0].Continue(r1[1:]); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParticipant_Continue_Bad_N_Messages(t *testing.T) {
	errRound1DataElements := errors.New("invalid number of expected round 1 data packets")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)

		// valid Round1Data with too few and too many packages (e.g. threshold instead of max signers)
		r1 := make([]*dkg.Round1Data, 0, c.maxParticipants)

		for i := range c.threshold {
			r1 = append(r1, p[i].Start())
		}

		if _, err := p[0].Continue(r1); err == nil || err.Error() != errRound1DataElements.Error() {
			t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
		}

		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants)

		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}
		r1 = append(r1, p[2].Start())

		if _, err := p[1].Continue(r1); err == nil || err.Error() != errRound1DataElements.Error() {
			t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
		}
	})
}

func TestParticipant_Continue_Bad_Proof_Z(t *testing.T) {
	expectedError := "ABORT - invalid signature: participant 4"

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)

		r1[3].ProofOfKnowledge.Z = c.group.NewScalar().Random()
		if _, err := p[1].Continue(r1); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Continue_Bad_Proof_R(t *testing.T) {
	expectedError := "ABORT - invalid signature: participant 3"

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)

		r1[2].ProofOfKnowledge.R = c.group.Base().Multiply(c.group.NewScalar().Random())
		if _, err := p[0].Continue(r1); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Continue_Bad_Commitment(t *testing.T) {
	errCommitmentNilElement := errors.New("commitment has nil element")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)

		// bad commitment[0]
		r1 := make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		r1[2].Commitment[0] = nil
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
	})
}

func TestParticipant_Finalize_Bad_Round1DataElements(t *testing.T) {
	errRound1DataElements := errors.New("invalid number of expected round 1 data packets")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)

		// valid Round1Data with too few and too many packages (e.g. threshold instead of max signers)
		r1 := make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.threshold {
			r1 = append(r1, p[i].Start())
		}

		for _, participant := range p {
			if _, err := participant.Finalize(r1, nil); err == nil || err.Error() != errRound1DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
			}
		}

		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants+1)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}
		r1 = append(r1, p[2].Start())

		for _, participant := range p {
			if _, err := participant.Finalize(r1, nil); err == nil || err.Error() != errRound1DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
			}
		}
	})
}

func TestParticipant_Finalize_Bad_Round2DataElements(t *testing.T) {
	errRound2DataElements := errors.New("invalid number of expected round 2 data packets")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// too short
		for _, participant := range p {
			d := r2[participant.Identifier]
			if _, err := participant.Finalize(r1, d[:len(d)-1]); err == nil ||
				err.Error() != errRound2DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound2DataElements, err)
			}
		}

		// too long
		for _, participant := range p {
			r, err := p[(participant.Identifier+1)%c.maxParticipants].Continue(r1)
			if err != nil {
				t.Fatal(err)
			}
			d := append(r2[participant.Identifier], r[(participant.Identifier+1)%c.maxParticipants])
			if _, err := participant.Finalize(r1, d); err == nil || err.Error() != errRound2DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound2DataElements, err)
			}
		}
	})
}

func TestParticipant_Finalize_Bad_Round2OwnPackage(t *testing.T) {
	errRound2OwnPackage := errors.New("mixed packages: received a round 2 package from itself")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// package comes from participant
		d := r2[p[0].Identifier]
		d[2].SenderIdentifier = p[0].Identifier
		d[2].RecipientIdentifier = p[1].Identifier
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != errRound2OwnPackage.Error() {
			t.Fatalf("expected error %q, got %q", errRound2OwnPackage, err)
		}
	})
}

func TestParticipant_Finalize_Bad_Round2InvalidReceiver(t *testing.T) {
	errRound2InvalidReceiver := errors.New("invalid receiver in round 2 package")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// package is not destined to recipient
		d := r2[p[0].Identifier]

		d[2].SenderIdentifier = p[4].Identifier
		d[2].RecipientIdentifier = p[3].Identifier

		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != errRound2InvalidReceiver.Error() {
			t.Fatalf("expected error %q, got %q", errRound2InvalidReceiver, err)
		}
	})
}

func TestParticipant_Finalize_Bad_Round2FaultyPackage(t *testing.T) {
	errRound2FaultyPackage := errors.New("malformed Round2Data package: sender and recipient are the same")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// package sender and receiver are the same
		d := r2[p[0].Identifier]

		d[3].SenderIdentifier = d[3].RecipientIdentifier
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != errRound2FaultyPackage.Error() {
			t.Fatalf("expected error %q, got %q", errRound2FaultyPackage, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentNotFound(t *testing.T) {
	errCommitmentNotFound := errors.New("commitment not found in Round 1 data for participant")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// r2 package sender is not in r1 data set
		d := r2[p[4].Identifier]

		expectedError := errCommitmentNotFound.Error() + ": 1"
		if _, err := p[4].Finalize(r1[1:], d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_InvalidSecretShare(t *testing.T) {
	errInvalidSecretShare := errors.New("ABORT - invalid secret share received from peer")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// secret share is not valid with commitment
		d := r2[p[4].Identifier]
		d[3].SecretShare = c.group.NewScalar().Random()

		expectedError := errInvalidSecretShare.Error() + ": 4"
		if _, err := p[4].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentNilElement(t *testing.T) {
	errInvalidSecretShare := errors.New("ABORT - invalid secret share received from peer")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// some commitment has a nil element
		r1[3].Commitment[1] = nil
		d := r2[p[0].Identifier]
		expectedError := errInvalidSecretShare.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentEmpty(t *testing.T) {
	errCommitmentEmpty := errors.New("commitment is empty")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)

		// some commitment is nil or empty
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)
		d := r2[p[0].Identifier]

		r1[3].Commitment = nil
		expectedError := errCommitmentEmpty.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}

		r1[3].Commitment = []*group.Element{}
		expectedError = errCommitmentEmpty.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestVerifyPublicKey_Bad_InvalidCiphersuite(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")

	testAllCases(t, func(c *testCase) {
		// Bad ciphersuite
		if err := dkg.VerifyPublicKey(0, 1, nil, nil); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error on invalid ciphersuite, want %q got %q", errInvalidCiphersuite, err)
		}
	})
}

func TestVerifyPublicKey_Bad_NilPubKey(t *testing.T) {
	errNilPubKey := errors.New("the provided public key is nil")

	testAllCases(t, func(c *testCase) {
		// nil pubkey
		if err := dkg.VerifyPublicKey(c.ciphersuite, 1, nil, nil); err == nil || err.Error() != errNilPubKey.Error() {
			t.Fatalf("expected error %q, got %q", errNilPubKey, err)
		}
	})
}

func TestVerifyPublicKey_Bad_VerificationShareFailed(t *testing.T) {
	errVerificationShareFailed := errors.New("failed to compute correct verification share")

	testAllCases(t, func(c *testCase) {
		// id and pubkey not related
		_, _, _, keyshares, registry := completeDKG(t, c)
		commitments := registry.Commitments()

		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].ID, keyshares[2].PublicKey, commitments); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}

		// bad pubkey
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].ID, c.group.NewElement(), commitments); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}

		// bad commitment
		commitments[4][2] = c.group.Base()
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].ID, keyshares[1].PublicKey, commitments); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}
	})
}

func TestVerifyPublicKey_Bad_MissingCommitments(t *testing.T) {
	errMissingRound1Data := errors.New("missing commitments")

	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].ID, keyshares[1].PublicKey, nil); err == nil ||
			err.Error() != errMissingRound1Data.Error() {
			t.Fatalf("expected error %q, got %q", errMissingRound1Data, err)
		}
	})
}

func TestVerifyPublicKey_Bad_NoCommitment(t *testing.T) {
	errNoCommitment := errors.New("empty commitment")

	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, registry := completeDKG(t, c)
		commitments := registry.Commitments()

		commitments[3] = nil
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].ID, keyshares[1].PublicKey, commitments); err == nil ||
			err.Error() != errNoCommitment.Error() {
			t.Fatalf("expected error %q, got %q", errNoCommitment, err)
		}
	})
}

func TestVerifyPublicKey_Bad_CommitmentNilElement(t *testing.T) {
	errCommitmentNilElement := errors.New("commitment has nil element")

	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, registry := completeDKG(t, c)
		commitments := registry.Commitments()

		commitments[2][2] = nil
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].ID, keyshares[1].PublicKey, commitments); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
	})
}

func TestComputeParticipantPublicKey_Bad_InvalidCiphersuite(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")

	testAllCases(t, func(c *testCase) {
		// invalid ciphersuite
		if _, err := dkg.ComputeParticipantPublicKey(0, 0, nil); err == nil ||
			err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error on invalid ciphersuite, want %q got %q", errInvalidCiphersuite, err)
		}
	})
}

func TestComputeParticipantPublicKey_Bad_MissingRound1Data(t *testing.T) {
	errMissingRound1Data := errors.New("missing commitments")

	testAllCases(t, func(c *testCase) {
		// nil r1 data
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, nil); err == nil ||
			err.Error() != errMissingRound1Data.Error() {
			t.Fatalf("expected error %q got %q", errMissingRound1Data, err)
		}
	})
}

func TestComputeParticipantPublicKey_Bad_NoCommitment(t *testing.T) {
	errNoCommitment := errors.New("empty commitment")

	testAllCases(t, func(c *testCase) {
		_, _, _, _, registry := completeDKG(t, c)
		commitments := registry.Commitments()

		// missing commitment
		commitments[3] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, commitments); err == nil ||
			err.Error() != errNoCommitment.Error() {
			t.Fatalf("expected error %q, got %q", errNoCommitment, err)
		}
	})
}

func TestComputeParticipantPublicKey_Bad_CommitmentNilElement(t *testing.T) {
	errCommitmentNilElement := errors.New("commitment has nil element")

	testAllCases(t, func(c *testCase) {
		_, _, _, _, registry := completeDKG(t, c)
		commitments := registry.Commitments()

		// commitment with nil element
		commitments[4][2] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, commitments); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}

		commitments[4][1] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 2, commitments); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
	})
}

func TestGroupPublicKey_BadCipher(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")

	if _, err := dkg.GroupPublicKeyFromRound1(dkg.Ciphersuite(2), nil); err == nil ||
		err.Error() != errInvalidCiphersuite.Error() {
		t.Fatalf("expected %q, got %q", errInvalidCiphersuite, err)
	}

	if _, err := dkg.GroupPublicKeyFromCommitments(dkg.Ciphersuite(2), nil); err == nil ||
		err.Error() != errInvalidCiphersuite.Error() {
		t.Fatalf("expected %q, got %q", errInvalidCiphersuite, err)
	}
}

func TestRegistry_Add_Bad(t *testing.T) {
	errPublicKeyShareRegistered := errors.New("the public key share is already registered")
	errPublicKeyShareCapacityExceeded := errors.New("can't add another public key share (full capacity)")

	testAllCases(t, func(c *testCase) {
		_, _, _, keyShares, _ := completeDKG(t, c)

		registry := c.ciphersuite.NewPublicKeyShareRegistry(c.threshold, c.maxParticipants)
		for _, keyShare := range keyShares {
			if err := registry.Add(keyShare.Public()); err != nil {
				t.Fatal(err)
			}
		}

		// add a public key share that has already been added
		if err := registry.Add(keyShares[0].Public()); err == nil ||
			err.Error() != errPublicKeyShareRegistered.Error() {
			t.Fatalf("expected error %q, got %q", errPublicKeyShareRegistered, err)
		}

		// add a share though we're full
		keyShares[0].ID = c.maxParticipants + 1
		if err := registry.Add(keyShares[0].Public()); err == nil ||
			err.Error() != errPublicKeyShareCapacityExceeded.Error() {
			t.Fatalf("expected error %q, got %q", errPublicKeyShareCapacityExceeded, err)
		}
	})
}

func TestRegistry_Get(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, _, registry := completeDKG(t, c)

		id := c.maxParticipants - 1
		if registry.Get(id) == nil {
			t.Fatal("Get returned nil")
		}

		id = c.maxParticipants + 1
		if registry.Get(id) != nil {
			t.Fatalf("Get returned non-nil: %d", id)
		}
	})
}

func TestRegistry_VerifyPublicKey(t *testing.T) {
	errNilPubKey := errors.New("the provided public key is nil")
	errRegistryHasNilPublicKey := errors.New("encountered a nil public key in registry")
	errVerifyBadPubKey := errors.New("the public key differs from the one registered")
	errVerifyUnknownID := errors.New("the requested identifier is not registered")
	testAllCases(t, func(c *testCase) {
		_, _, _, _, registry := completeDKG(t, c)
		id := uint16(1)
		pk := registry.PublicKeyShares[id].PublicKey

		if err := registry.VerifyPublicKey(id, pk); err != nil {
			t.Fatalf("unexpected error %q", err)
		}

		if err := registry.VerifyPublicKey(id, nil); err == nil || err.Error() != errNilPubKey.Error() {
			t.Fatalf("expecter error %q, got %q", errNilPubKey, err)
		}

		expected := fmt.Errorf("%w for ID %d", errVerifyBadPubKey, id)
		if err := registry.VerifyPublicKey(id, c.group.NewElement()); err == nil || err.Error() != expected.Error() {
			t.Fatalf("expecter error %q, got %q", expected, err)
		}

		registry.PublicKeyShares[1].PublicKey = nil
		expected = fmt.Errorf("%w for ID %d", errRegistryHasNilPublicKey, id)
		if err := registry.VerifyPublicKey(id, c.group.NewElement()); err == nil || err.Error() != expected.Error() {
			t.Fatalf("expecter error %q, got %q", expected, err)
		}

		expected = fmt.Errorf("%w: %q", errVerifyUnknownID, 0)
		if err := registry.VerifyPublicKey(0, c.group.NewElement()); err == nil || err.Error() != expected.Error() {
			t.Fatalf("expecter error %q, got %q", expected, err)
		}
	})
}
