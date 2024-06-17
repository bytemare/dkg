// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests_test

import (
	"errors"
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
		r2 := make(map[uint64][]*dkg.Round2Data, c.maxParticipants)
		for i := range c.maxParticipants {
			r, err := p[i].Continue(r1)
			if err != nil {
				t.Fatal(err)
			}

			// triage r2 data for Finalize()
			for id, data := range r {
				if r2[id] == nil {
					r2[id] = make([]*dkg.Round2Data, 0, c.maxParticipants-1)
				}
				r2[id] = append(r2[id], data)
			}
		}

		// Step 3: Clean the proofs.
		// This must be called by each participant on their copy of the r1DataSet.
		for _, d := range r1 {
			d.ProofOfKnowledge.Clear()
		}

		// Step 4: Finalize and test outputs.
		quals := []uint64{1, 3, 5}
		keyShares := make([]*secretsharing.KeyShare, 0, len(quals))
		pubKey, _ := dkg.GroupPublicKey(c.ciphersuite, r1)
		for _, participant := range p {
			keyShare, gpk, err := participant.Finalize(r1, r2[participant.Identifier])
			if err != nil {
				t.Fatal()
			}

			if gpk.Equal(pubKey) != 1 {
				t.Fatalf("expected same public key")
			}

			if keyShare.PublicKey.Equal(c.group.Base().Multiply(keyShare.SecretKey)) != 1 {
				t.Fatal("expected equality")
			}

			if err := dkg.VerifyPublicKey(c.ciphersuite, participant.Identifier, keyShare.PublicKey, r1); err != nil {
				t.Fatal(err)
			}

			// Assemble a subset to test key recovery.
			if slices.Contains(quals, participant.Identifier) { // only take the selected identifiers
				keyShares = append(keyShares, &secretsharing.KeyShare{
					Identifier: keyShare.Identifier,
					SecretKey:  keyShare.SecretKey,
				})
			}
		}

		// Verify the threshold scheme by combining a subset of the shares.
		secret, err := secretsharing.Combine(c.group, keyShares)
		if err != nil {
			t.Fatal(err)
		}

		pk := c.group.Base().Multiply(secret)
		if pk.Equal(pubKey) != 1 {
			t.Fatal("expected recovered secret to be compatible with public key")
		}
	})
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

func testMakePolynomial(g group.Group, n uint) secretsharing.Polynomial {
	p := secretsharing.NewPolynomial(n)
	for i := range n {
		p[i] = g.NewScalar().Random()
	}

	return p
}

func TestCiphersuite_NewParticipant(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold); err != nil {
			t.Fatal(err)
		}

		poly := testMakePolynomial(c.group, c.threshold)
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold, poly...); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")
	errParticipantIDZero := errors.New("participant ID has forbidden value 0")
	errPolynomialLength := errors.New("invalid polynomial length")
	errPolyHasNilCoeff := errors.New("invalid polynomial: the polynomial has a nil coefficient")
	errPolyHasZeroCoeff := errors.New("invalid polynomial: one of the polynomial's coefficients is zero")
	errPolyHasDuplicates := errors.New("invalid polynomial: the polynomial has duplicate coefficients")
	testAllCases(t, func(c *testCase) {
		// Bad ciphersuite
		if _, err := dkg.Ciphersuite(0).NewParticipant(1, c.threshold, c.maxParticipants); err == nil ||
			err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error on invalid ciphersuite, want %q got %q", errInvalidCiphersuite, err)
		}

		// id == 0
		if _, err := c.ciphersuite.NewParticipant(0, c.threshold, c.maxParticipants); err == nil ||
			err.Error() != errParticipantIDZero.Error() {
			t.Fatalf("expected error on id == 0, want %q got %q", errParticipantIDZero, err)
		}

		// poly has bad length
		poly := make([]*group.Scalar, c.threshold-1)
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold, poly...); err == nil ||
			err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}

		poly = make([]*group.Scalar, c.threshold+1)
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold, poly...); err == nil ||
			err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}

		// poly has nil coeff
		poly = make([]*group.Scalar, c.threshold)
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold, poly...); err == nil ||
			err.Error() != errPolyHasNilCoeff.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasNilCoeff, err)
		}

		poly = testMakePolynomial(c.group, c.threshold)
		poly[1] = nil
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold, poly...); err == nil ||
			err.Error() != errPolyHasNilCoeff.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasNilCoeff, err)
		}

		// poly has a zero coefficient
		poly = testMakePolynomial(c.group, c.threshold)
		poly[1].Zero()
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold, poly...); err == nil ||
			err.Error() != errPolyHasZeroCoeff.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasZeroCoeff, err)
		}

		// poly has duplicates
		poly = testMakePolynomial(c.group, c.threshold)
		poly[1].Set(poly[2])
		if _, err := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold, poly...); err == nil ||
			err.Error() != errPolyHasDuplicates.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasDuplicates, err)
		}
	})
}

func (c *testCase) makeParticipants(t *testing.T) []*dkg.Participant {
	ps := make([]*dkg.Participant, 0, c.maxParticipants)
	for i := range uint64(c.maxParticipants) {
		p, err := c.ciphersuite.NewParticipant(i+1, c.maxParticipants, c.threshold)
		if err != nil {
			t.Fatal(err)
		}

		ps = append(ps, p)
	}

	return ps
}

func TestParticipant_Continue(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		// valid r1DataSet set with and without own package
		p := c.makeParticipants(t)
		r1 := make([]*dkg.Round1Data, c.maxParticipants)

		for i := range c.maxParticipants {
			r1[i] = p[i].Start()
		}

		if _, err := p[0].Continue(r1); err != nil {
			t.Fatal(err)
		}

		// valid r1dataset set without own package
		if _, err := p[0].Continue(r1[1:]); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParticipant_Continue_Bad(t *testing.T) {
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

		// bad z
		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		r1[3].ProofOfKnowledge.Z = c.group.NewScalar().Random()

		expectedError := "invalid signature: participant 4"
		if _, err := p[1].Continue(r1); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}

		// bad r
		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		r1[2].ProofOfKnowledge.R = c.group.Base().Multiply(c.group.NewScalar().Random())

		expectedError = "invalid signature: participant 3"
		if _, err := p[0].Continue(r1); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad(t *testing.T) {
	errRound1DataElements := errors.New("invalid number of expected round 1 data packets")
	errRound2DataElements := errors.New("invalid number of expected round 2 data packets")
	errRound2OwnPackage := errors.New("mixed packages: received a round 2 package from itself")
	errRound2InvalidReceiver := errors.New("invalid receiver in round 2 package")
	errRound2FaultyPackage := errors.New("malformed Round2Data package: sender and recipient are the same")
	errCommitmentNotFound := errors.New("commitment not found in Round 1 data for participant")
	errInvalidSecretShare := errors.New("invalid secret share received from peer")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)

		// valid Round1Data with too few and too many packages (e.g. threshold instead of max signers)
		r1 := make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.threshold {
			r1 = append(r1, p[i].Start())
		}

		for _, participant := range p {
			if _, _, err := participant.Finalize(r1, nil); err == nil || err.Error() != errRound1DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
			}
		}

		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants+1)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}
		r1 = append(r1, p[2].Start())

		for _, participant := range p {
			if _, _, err := participant.Finalize(r1, nil); err == nil || err.Error() != errRound1DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
			}
		}

		// incompatible r1 and r2 dataset lengths
		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		r2 := make(map[uint64][]*dkg.Round2Data, c.maxParticipants)
		for i := range c.maxParticipants {
			r, err := p[i].Continue(r1)
			if err != nil {
				t.Fatal(err)
			}

			// triage r2 data for Finalize()
			for id, data := range r {
				if r2[id] == nil {
					r2[id] = make([]*dkg.Round2Data, 0, c.maxParticipants)
				}
				r2[id] = append(r2[id], data)
			}
		}

		// too short
		for _, participant := range p {
			d := r2[participant.Identifier]
			if _, _, err := participant.Finalize(r1, d[:len(d)-1]); err == nil ||
				err.Error() != errRound2DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound2DataElements, err)
			}
		}

		// too long
		for _, participant := range p {
			r, err := p[(participant.Identifier+1)%uint64(c.maxParticipants)].Continue(r1)
			if err != nil {
				t.Fatal(err)
			}
			d := append(r2[participant.Identifier], r[(participant.Identifier+1)%uint64(c.maxParticipants)])
			if _, _, err := participant.Finalize(r1, d); err == nil || err.Error() != errRound2DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound2DataElements, err)
			}
		}

		// package sender and receiver are the same
		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		r2 = make(map[uint64][]*dkg.Round2Data, c.maxParticipants)
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

		d := r2[p[0].Identifier]
		d[3].SenderIdentifier = d[3].RecipientIdentifier
		if _, _, err := p[0].Finalize(r1, d); err == nil || err.Error() != errRound2FaultyPackage.Error() {
			t.Fatalf("expected error %q, got %q", errRound2FaultyPackage, err)
		}

		// package comes from participant
		d[2].SenderIdentifier = p[0].Identifier
		d[2].RecipientIdentifier = p[1].Identifier
		if _, _, err := p[0].Finalize(r1, d); err == nil || err.Error() != errRound2OwnPackage.Error() {
			t.Fatalf("expected error %q, got %q", errRound2OwnPackage, err)
		}

		// package is not destined to recipient
		d[2].SenderIdentifier = p[4].Identifier
		d[2].RecipientIdentifier = p[3].Identifier
		if _, _, err := p[0].Finalize(r1, d); err == nil || err.Error() != errRound2InvalidReceiver.Error() {
			t.Fatalf("expected error %q, got %q", errRound2InvalidReceiver, err)
		}
		d[2].RecipientIdentifier = p[0].Identifier

		// r2 package sender is not in r1 data set
		d = r2[p[4].Identifier]
		expectedError := errCommitmentNotFound.Error() + ": 1"
		if _, _, err := p[4].Finalize(r1[1:], d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}

		// secret share is not valid with commitment
		d = r2[p[4].Identifier]
		d[3].SecretShare = c.group.NewScalar().Random()
		expectedError = errInvalidSecretShare.Error() + ": 4"
		if _, _, err := p[4].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestVerifyPublicKey(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")
	errNilPubKey := errors.New("the provided public key is nil")
	errVerificationShareFailed := errors.New("failed to compute correct verification share")
	errMissingRound1Data := errors.New("provided round 1 data set is empty")
	errMissingPackageRound1 := errors.New("missing package in round 1 data set")
	errNoCommitment := errors.New("empty commitment in package")
	errCommitmentNilElement := errors.New("commitment has nil element")

	testAllCases(t, func(c *testCase) {
		// Bad ciphersuite
		if err := dkg.VerifyPublicKey(0, 1, nil, nil); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error on invalid ciphersuite, want %q got %q", errInvalidCiphersuite, err)
		}

		// nil pubkey
		if err := dkg.VerifyPublicKey(c.ciphersuite, 1, nil, nil); err == nil || err.Error() != errNilPubKey.Error() {
			t.Fatalf("expected error %q, got %q", errNilPubKey, err)
		}

		// id and pubkey not related
		p := c.makeParticipants(t)

		r1 := make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		r2 := make(map[uint64][]*dkg.Round2Data, c.maxParticipants)
		for i := range c.maxParticipants {
			r, err := p[i].Continue(r1)
			if err != nil {
				t.Fatal(err)
			}

			// triage r2 data for Finalize()
			for id, data := range r {
				if r2[id] == nil {
					r2[id] = make([]*dkg.Round2Data, 0, c.maxParticipants-1)
				}
				r2[id] = append(r2[id], data)
			}
		}

		keyshares := make([]*dkg.KeyShare, 0, c.maxParticipants)
		for _, participant := range p {
			ks, _, err := participant.Finalize(r1, r2[participant.Identifier])
			if err != nil {
				t.Fatal(err)
			}

			keyshares = append(keyshares, ks)
		}

		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier, keyshares[2].PublicKey, r1); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}

		// bad pubkey
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier, c.group.NewElement(), r1); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}

		// bad commitment
		r1[4].Commitment[2] = c.group.Base()
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier, keyshares[1].PublicKey, r1); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}

		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier, keyshares[1].PublicKey, nil); err == nil ||
			err.Error() != errMissingRound1Data.Error() {
			t.Fatalf("expected error %q, got %q", errMissingRound1Data, err)
		}

		r1[4] = nil
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier, keyshares[1].PublicKey, r1); err == nil ||
			err.Error() != errMissingPackageRound1.Error() {
			t.Fatalf("expected error %q, got %q", errMissingPackageRound1, err)
		}

		r1[3].Commitment = nil
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier, keyshares[1].PublicKey, r1); err == nil ||
			err.Error() != errNoCommitment.Error() {
			t.Fatalf("expected error %q, got %q", errNoCommitment, err)
		}

		r1[2].Commitment[2] = nil
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier, keyshares[1].PublicKey, r1); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
	})
}

func TestComputeParticipantPublicKey(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")
	errMissingRound1Data := errors.New("provided round 1 data set is empty")
	errMissingPackageRound1 := errors.New("missing package in round 1 data set")
	errNoCommitment := errors.New("empty commitment in package")
	errCommitmentNilElement := errors.New("commitment has nil element")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		// invalid ciphersuite
		if _, err := dkg.ComputeParticipantPublicKey(0, 0, nil); err == nil ||
			err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error on invalid ciphersuite, want %q got %q", errInvalidCiphersuite, err)
		}

		// nil r1 data
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, nil); err == nil ||
			err.Error() != errMissingRound1Data.Error() {
			t.Fatalf("expected error %q got %q", errMissingRound1Data, err)
		}

		// missing package
		r1[4] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, r1); err == nil ||
			err.Error() != errMissingPackageRound1.Error() {
			t.Fatalf("expected error %q, got %q", errMissingPackageRound1, err)
		}

		// missing commitment
		r1[3].Commitment = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, r1); err == nil ||
			err.Error() != errNoCommitment.Error() {
			t.Fatalf("expected error %q, got %q", errNoCommitment, err)
		}

		// commitment with nil element
		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants)
		for i := range c.maxParticipants {
			r1 = append(r1, p[i].Start())
		}

		r1[4].Commitment[2] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, r1); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}

		r1[4].Commitment[1] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 2, r1); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}

		r1[4].Commitment[2] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 2, r1); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
	})
}
