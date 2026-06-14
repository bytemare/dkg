// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
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

	"github.com/bytemare/ecc"
	"github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/dkg"

	secretsharing "github.com/bytemare/secret-sharing"
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
			r1[i] = mustStart(t, p[i])
		}

		// Step 2: Continue and assemble + triage packages.
		r2 := c.runRound2(t, p, r1)

		// Step 3: Clean the proofs.
		// This must be called by each participant on their copy of the r1DataSet.
		pubKey, _ := dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		for _, d := range r1 {
			d.ProofOfKnowledge.Clear()
		}

		// Step 4: Finalize and test outputs.
		quals := []uint16{1, 3, 5}
		keyShares := make([]*keys.KeyShare, 0, len(quals))
		publicKeyShares := make([]*keys.PublicKeyShare, 0, c.maxParticipants)
		for _, participant := range p {
			keyShare, err := participant.Finalize(r1, r2[participant.Identifier])
			if err != nil {
				t.Fatal(err)
			}

			if !keyShare.VerificationKey().Equal(pubKey) {
				t.Fatalf("expected same public key")
			}

			if !keyShare.PublicKey().Equal(c.group.Base().Multiply(keyShare.SecretKey())) {
				t.Fatal("expected equality")
			}

			publicKeyShares = append(publicKeyShares, keyShare.PublicKeyShare())

			// Assemble a subset to test key recovery.
			if slices.Contains(quals, participant.Identifier) { // only take the selected identifiers
				keyShares = append(keyShares, keyShare)
			}
		}

		registry, err := keys.NewPublicKeyShareRegistry(
			c.group,
			c.threshold,
			c.maxParticipants,
			pubKey,
			publicKeyShares,
		)
		if err != nil {
			t.Fatal(err)
		}

		{
			for _, k := range keyShares {
				if err := registry.ContainsPublicKey(k.Identifier(), k.PublicKey()); err != nil {
					t.Fatal(err)
				}
			}
		}

		// Verify the threshold scheme by combining a subset of the shares.
		{
			combinedKeyShares := make([]*keys.KeyShare, 0, len(quals))
			for _, k := range keyShares {
				combinedKeyShares = append(combinedKeyShares, k)
			}

			secret, err := secretsharing.CombineShares(combinedKeyShares, c.threshold)
			if err != nil {
				t.Fatal(err)
			}

			pk := c.group.Base().Multiply(secret)
			if !pk.Equal(pubKey) {
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

func (c *testCase) makeParticipantsWithZeroInteriorCoeff(t *testing.T, id uint16) []*dkg.Participant {
	if c.threshold < 3 {
		t.Skip("test requires an interior coefficient")
	}

	ps := make([]*dkg.Participant, 0, c.maxParticipants)
	for i := range c.maxParticipants {
		var polynomial secretsharing.Polynomial
		if i+1 == id {
			polynomial = testMakePolynomial(c.group, c.threshold)
			polynomial[1].Zero()
		}

		p, err := c.ciphersuite.NewParticipant(i+1, c.threshold, c.maxParticipants, polynomial...)
		if err != nil {
			t.Fatal(err)
		}

		ps = append(ps, p)
	}

	return ps
}

func (c *testCase) makeParticipantsWithCancellingHighestDegreeCoeff(t *testing.T) []*dkg.Participant {
	if c.threshold < 2 {
		t.Skip("test requires a non-constant highest-degree coefficient")
	}

	ps := make([]*dkg.Participant, 0, c.maxParticipants)
	highestDegreeSum := c.group.NewScalar()
	for i := range c.maxParticipants {
		polynomial := testMakePolynomial(c.group, c.threshold)

		if i+1 < c.maxParticipants {
			polynomial[c.threshold-1] = c.group.NewScalar().One()
			highestDegreeSum.Add(polynomial[c.threshold-1])
		} else {
			polynomial[c.threshold-1] = c.group.NewScalar().Zero().Subtract(highestDegreeSum)
			if polynomial[c.threshold-1].IsZero() {
				t.Fatal("test setup produced a zero highest-degree coefficient")
			}
		}

		p, err := c.ciphersuite.NewParticipant(i+1, c.threshold, c.maxParticipants, polynomial...)
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
		r1Item, err := p[i].Start()
		if err != nil {
			panic(err)
		}
		r1 = append(r1, r1Item)
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
) []*keys.KeyShare {
	keyShares := make([]*keys.KeyShare, 0, c.maxParticipants)
	for _, participant := range participants {
		ks, err := participant.Finalize(r1, r2[participant.Identifier])
		if err != nil {
			t.Fatal(err)
		}

		keyShares = append(keyShares, ks)
	}

	return keyShares
}

func makeRegistry(t *testing.T, c *testCase, keyShares []*keys.KeyShare) *keys.PublicKeyShareRegistry {
	publicKeyShares := make([]*keys.PublicKeyShare, len(keyShares))
	for i, keyShare := range keyShares {
		publicKeyShares[i] = keyShare.PublicKeyShare()
	}

	registry, err := keys.NewPublicKeyShareRegistry(
		c.group,
		c.threshold,
		c.maxParticipants,
		keyShares[0].VerificationKey(),
		publicKeyShares,
	)
	if err != nil {
		t.Fatal(err)
	}

	return registry
}

func commitmentsFromRound1(r1 []*dkg.Round1Data) [][]*ecc.Element {
	commitments := make([][]*ecc.Element, len(r1))
	for i, data := range r1 {
		commitments[i] = make([]*ecc.Element, len(data.Commitment))
		for j, coefficient := range data.Commitment {
			if coefficient != nil {
				commitments[i][j] = coefficient.Copy()
			}
		}
	}

	return commitments
}

func requireErrorString(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil || err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err)
	}
}

func mustStart(t *testing.T, p *dkg.Participant) *dkg.Round1Data {
	t.Helper()

	r1, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}

	return r1
}

func cloneRound1(t *testing.T, r1 *dkg.Round1Data) *dkg.Round1Data {
	t.Helper()

	clone := new(dkg.Round1Data)
	if err := clone.Decode(r1.Encode()); err != nil {
		t.Fatal(err)
	}

	return clone
}

func completeDKG(
	t *testing.T,
	c *testCase,
) ([]*dkg.Participant, []*dkg.Round1Data, map[uint16][]*dkg.Round2Data, []*keys.KeyShare, *keys.PublicKeyShareRegistry) {
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
		if ecc.Group(c.ciphersuite) != c.group {
			t.Fatal(errUnexpectedCiphersuiteGroup)
		}

		if c.ciphersuite.Group() != ecc.Group(c.ciphersuite) {
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

func testMakePolynomial(g ecc.Group, n uint16) secretsharing.Polynomial {
	p := secretsharing.NewPolynomial(n)
	for i := range n {
		p[i] = g.NewScalar().Random()
	}

	return p
}

func testOtherGroup(g ecc.Group) ecc.Group {
	if g == ecc.Ristretto255Sha512 {
		return ecc.P256Sha256
	}

	return ecc.Ristretto255Sha512
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

func TestCiphersuite_NewParticipant_Bad_ThresholdParameters(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		if p, err := c.ciphersuite.NewParticipant(1, c.threshold, 0); err == nil ||
			err.Error() != errors.New("max signers is 0").Error() || p != nil {
			t.Fatalf("expected max signers validation error, got participant=%v err=%q", p, err)
		}

		if p, err := c.ciphersuite.NewParticipant(1, 0, c.maxParticipants); err == nil ||
			err.Error() != errors.New("threshold is 0").Error() || p != nil {
			t.Fatalf("expected zero threshold validation error, got participant=%v err=%q", p, err)
		}

		if p, err := c.ciphersuite.NewParticipant(1, c.maxParticipants+1, c.maxParticipants); err == nil ||
			err.Error() != errors.New("threshold is above max signers").Error() || p != nil {
			t.Fatalf("expected threshold range validation error, got participant=%v err=%q", p, err)
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
		errParticipantIDZero := fmt.Errorf("identifier is above authorized range [1:%d]: %d", c.maxParticipants, id)
		if _, err := c.ciphersuite.NewParticipant(id, c.threshold, c.maxParticipants); err == nil ||
			err.Error() != errParticipantIDZero.Error() {
			t.Fatalf("expected error on id == 0, want %q got %q", errParticipantIDZero, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_PolynomialLength(t *testing.T) {
	errPolynomialLength := errors.New("invalid polynomial length")

	testAllCases(t, func(c *testCase) {
		poly := make([]*ecc.Scalar, c.threshold-1)
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}

		poly = make([]*ecc.Scalar, c.threshold+1)
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_PolyHasNilCoeff(t *testing.T) {
	errPolyHasNilCoeff := errors.New("invalid polynomial: the polynomial has a nil coefficient")

	testAllCases(t, func(c *testCase) {
		poly := make([]*ecc.Scalar, c.threshold)
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

func TestCiphersuite_NewParticipant_Bad_PolyHasZeroSecret(t *testing.T) {
	errSecretIsZero := errors.New("invalid polynomial: the provided secret is zero")

	testAllCases(t, func(c *testCase) {
		poly := testMakePolynomial(c.group, c.threshold)
		poly[0].Zero()
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errSecretIsZero.Error() {
			t.Fatalf("expected error %q, got %q", errSecretIsZero, err)
		}
	})
}

func TestCiphersuite_NewParticipant_Bad_PolyHasZeroLeadingCoeff(t *testing.T) {
	errPolyHasZeroCoeff := errors.New("invalid polynomial: the highest-degree coefficient is zero")

	testAllCases(t, func(c *testCase) {
		poly := testMakePolynomial(c.group, c.threshold)
		poly[c.threshold-1].Zero()
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err == nil ||
			err.Error() != errPolyHasZeroCoeff.Error() {
			t.Fatalf("expected error %q, got %q", errPolyHasZeroCoeff, err)
		}
	})
}

func TestCiphersuite_NewParticipant_AllowsInteriorZeroCoeff(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		poly := testMakePolynomial(c.group, c.threshold)
		poly[1].Zero()
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCiphersuite_NewParticipant_AllowsDuplicateCoefficients(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		poly := testMakePolynomial(c.group, c.threshold)
		poly[1].Set(poly[2])
		if _, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants, poly...); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParticipant_StartWithRandom_BadNonce(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants)
		if err != nil {
			t.Fatal(err)
		}

		zeroNonce := c.group.NewScalar()
		if _, err := p.StartWithRandom(zeroNonce); err == nil || err.Error() != "the provided nonce is zero" {
			t.Fatalf("expected zero nonce error, got %q", err)
		}

		wrongGroupNonce := testOtherGroup(c.group).NewScalar().Random()
		if _, err := p.StartWithRandom(wrongGroupNonce); err == nil ||
			err.Error() != "the provided nonce has incompatible EC group" {
			t.Fatalf("expected wrong group nonce error, got %q", err)
		}
	})
}

func TestParticipant_Start_BadReceiverState(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		var nilParticipant *dkg.Participant
		if _, err := nilParticipant.Start(); err == nil {
			t.Fatal("expected nil participant start to fail")
		}

		if _, err := nilParticipant.StartWithRandom(nil); err == nil {
			t.Fatal("expected nil participant start with random to fail")
		}

		if _, err := (&dkg.Participant{}).Start(); err == nil {
			t.Fatal("expected uninitialized participant start to fail")
		}

		if _, err := (&dkg.Participant{}).StartWithRandom(nil); err == nil {
			t.Fatal("expected uninitialized participant start with random to fail")
		}
	})
}

func TestParticipant_Start_ReturnsDefensiveCommitmentCopy(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r1Copy := make([]*dkg.Round1Data, len(r1))
		for i, data := range r1 {
			r1Copy[i] = cloneRound1(t, data)
		}

		r1[0].Commitment[0] = c.group.NewElement()
		r1[0] = r1Copy[0]

		r2 := c.runRound2(t, p, r1)
		keyShares := c.finalize(t, p, r1, r2)

		pubKey, err := dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		if err != nil {
			t.Fatal(err)
		}

		if !keyShares[0].VerificationKey().Equal(pubKey) {
			t.Fatal("expected defensive copy to preserve the participant commitment")
		}
	})
}

func TestParticipant_StateMachine(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		t.Run("start", func(t *testing.T) {
			p, err := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := p.Start(); err != nil {
				t.Fatal(err)
			}

			if _, err := p.Start(); err == nil {
				t.Fatal("expected second start to fail")
			}

			if _, err := p.StartWithRandom(c.group.NewScalar().Random()); err == nil {
				t.Fatal("expected out-of-order start with random to fail")
			}
		})

		t.Run("continue", func(t *testing.T) {
			p := c.makeParticipants(t)
			r1 := c.runRound1(p)

			r1Good := cloneRound1(t, r1[2])
			r1Bad := cloneRound1(t, r1[2])
			r1Bad.ProofOfKnowledge.Clear()
			r1[2] = r1Bad

			if _, err := p[0].Continue(r1); err == nil {
				t.Fatal("expected continue with invalid proof to fail")
			}

			r1[2] = r1Good
			if _, err := p[0].Continue(r1); err != nil {
				t.Fatal(err)
			}

			if _, err := p[0].Continue(r1); err == nil {
				t.Fatal("expected second continue to fail")
			}
		})

		t.Run("finalize", func(t *testing.T) {
			p := c.makeParticipants(t)
			r1 := c.runRound1(p)
			r2 := c.runRound2(t, p, r1)

			r1Bad := make([]*dkg.Round1Data, len(r1))
			for i, data := range r1 {
				r1Bad[i] = cloneRound1(t, data)
			}
			r1Bad[2].Commitment[0] = c.group.NewElement()

			if _, err := p[0].Finalize(r1Bad, r2[p[0].Identifier]); err == nil {
				t.Fatal("expected finalize with mismatched commitment to fail")
			}

			r1Cleared := make([]*dkg.Round1Data, len(r1))
			for i, data := range r1 {
				r1Cleared[i] = cloneRound1(t, data)
				r1Cleared[i].ProofOfKnowledge.Clear()
			}

			if _, err := p[0].Finalize(r1Cleared, r2[p[0].Identifier]); err != nil {
				t.Fatal(err)
			}

			if _, err := p[0].Finalize(r1Cleared, r2[p[0].Identifier]); err == nil {
				t.Fatal("expected second finalize to fail")
			}
		})
	})
}

func TestParticipant_Continue_RetryAfterFailedContinue(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)

		pubKey, err := dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		if err != nil {
			t.Fatal(err)
		}

		badR1 := make([]*dkg.Round1Data, len(r1))
		for i, data := range r1 {
			badR1[i] = cloneRound1(t, data)
		}
		badR1[2].ProofOfKnowledge.Clear()

		if _, err := p[0].Continue(badR1); err == nil {
			t.Fatal("expected continue with invalid proof to fail")
		}

		r2 := make(map[uint16][]*dkg.Round2Data, c.maxParticipants)
		accumulate := func(out map[uint16]*dkg.Round2Data) {
			for id, data := range out {
				r2[id] = append(r2[id], data)
			}
		}

		out, err := p[0].Continue(r1)
		if err != nil {
			t.Fatal(err)
		}
		accumulate(out)

		for i := 1; i < len(p); i++ {
			out, err = p[i].Continue(r1)
			if err != nil {
				t.Fatal(err)
			}
			accumulate(out)
		}

		for _, participant := range p {
			keyShare, err := participant.Finalize(r1, r2[participant.Identifier])
			if err != nil {
				t.Fatal(err)
			}

			if !keyShare.VerificationKey().Equal(pubKey) {
				t.Fatal("expected same public key after retry")
			}

			if !keyShare.PublicKey().Equal(c.group.Base().Multiply(keyShare.SecretKey())) {
				t.Fatal("expected public key share to match secret key after retry")
			}
		}
	})
}

func TestParticipant_Finalize_RetryAfterFailedFinalize(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		pubKey, err := dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		if err != nil {
			t.Fatal(err)
		}

		badR2 := append([]*dkg.Round2Data(nil), r2[p[0].Identifier]...)
		last := len(badR2) - 1
		badR2[last] = &dkg.Round2Data{
			Group:               badR2[last].Group,
			SenderIdentifier:    badR2[last].SenderIdentifier,
			RecipientIdentifier: badR2[last].RecipientIdentifier,
			SecretShare:         c.group.NewScalar().Random(),
		}

		if _, err := p[0].Finalize(r1, badR2); err == nil {
			t.Fatal("expected finalize with invalid round 2 share to fail")
		}

		keyShare, err := p[0].Finalize(r1, r2[p[0].Identifier])
		if err != nil {
			t.Fatal(err)
		}

		if !keyShare.VerificationKey().Equal(pubKey) {
			t.Fatal("expected same public key after retry")
		}

		if !keyShare.PublicKey().Equal(c.group.Base().Multiply(keyShare.SecretKey())) {
			t.Fatal("expected public key share to match secret key after retry")
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
		r1WithoutOwn := append(append([]*dkg.Round1Data{}, r1[:1]...), r1[2:]...)
		if _, err := p[1].Continue(r1WithoutOwn); err != nil {
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
			r1 = append(r1, mustStart(t, p[i]))
		}

		if _, err := p[0].Continue(r1); err == nil || err.Error() != errRound1DataElements.Error() {
			t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
		}

		p = c.makeParticipants(t)
		r1 = make([]*dkg.Round1Data, 0, c.maxParticipants)

		for i := range c.maxParticipants {
			r1 = append(r1, mustStart(t, p[i]))
		}
		r1 = append(r1, r1[2])

		if _, err := p[1].Continue(r1); err == nil || err.Error() != errRound1DataElements.Error() {
			t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
		}
	})
}

func TestParticipant_Continue_Bad_Round1SenderIdentifier(t *testing.T) {
	errParticipantIDZero := errors.New("identifier is 0")
	errRound1NilPackage := errors.New("round 1 data packet is nil")
	errRound1MissingPackage := errors.New("missing round 1 package from participant")
	errRound1DuplicateSender := errors.New("duplicate round 1 package from participant")

	testAllCases(t, func(c *testCase) {
		setup := func() ([]*dkg.Participant, []*dkg.Round1Data) {
			p := c.makeParticipants(t)
			return p, c.runRound1(p)
		}

		p, r1 := setup()
		r1[2] = nil
		_, err := p[0].Continue(r1)
		requireErrorString(t, err, errRound1NilPackage.Error())

		p, r1 = setup()
		r1[2].SenderIdentifier = 0
		_, err = p[0].Continue(r1)
		requireErrorString(t, err, errParticipantIDZero.Error())

		p, r1 = setup()
		r1[2].SenderIdentifier = c.maxParticipants + 1
		_, err = p[0].Continue(r1)
		requireErrorString(
			t,
			err,
			fmt.Sprintf("identifier is above authorized range [1:%d]: %d", c.maxParticipants, c.maxParticipants+1),
		)

		p, r1 = setup()
		r1[3].SenderIdentifier = r1[2].SenderIdentifier
		_, err = p[0].Continue(r1)
		requireErrorString(t, err, errRound1DuplicateSender.Error()+": 3")

		p, r1 = setup()
		_, err = p[0].Continue(r1[:int(c.maxParticipants-1)])
		requireErrorString(t, err, errRound1MissingPackage.Error()+": 5")
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

func TestParticipant_Continue_Bad_Proof_Malformed(t *testing.T) {
	expectedError := "ABORT - invalid signature: participant 3"

	testAllCases(t, func(c *testCase) {
		setup := func() ([]*dkg.Participant, []*dkg.Round1Data) {
			p := c.makeParticipants(t)
			return p, c.runRound1(p)
		}

		p, r1 := setup()
		r1[2].ProofOfKnowledge = nil
		_, err := p[0].Continue(r1)
		requireErrorString(t, err, expectedError)

		p, r1 = setup()
		r1[2].ProofOfKnowledge.R = nil
		_, err = p[0].Continue(r1)
		requireErrorString(t, err, expectedError)

		p, r1 = setup()
		r1[2].ProofOfKnowledge.Z = nil
		_, err = p[0].Continue(r1)
		requireErrorString(t, err, expectedError)

		p, r1 = setup()
		r1[2].ProofOfKnowledge.R = testOtherGroup(c.group).Base()
		_, err = p[0].Continue(r1)
		requireErrorString(t, err, expectedError)

		p, r1 = setup()
		r1[2].ProofOfKnowledge.Z = testOtherGroup(c.group).NewScalar().Random()
		_, err = p[0].Continue(r1)
		requireErrorString(t, err, expectedError)
	})
}

func TestParticipant_Continue_Bad_Commitment(t *testing.T) {
	errPolynomialLength := errors.New("invalid polynomial length")
	errCommitmentNilElement := errors.New("commitment has nil element")
	errCommitmentIdentityElement := errors.New("commitment has identity element")
	errCommitmentWrongGroup := errors.New("commitment element has incompatible EC group")
	errCommitmentEmpty := errors.New("commitment is empty")

	testAllCases(t, func(c *testCase) {
		setup := func() ([]*dkg.Participant, []*dkg.Round1Data) {
			p := c.makeParticipants(t)
			return p, c.runRound1(p)
		}

		p, r1 := setup()
		r1[2].Commitment = nil
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errCommitmentEmpty.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentEmpty, err)
		}

		p, r1 = setup()
		r1[2].Commitment = []*ecc.Element{}
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errCommitmentEmpty.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentEmpty, err)
		}

		p, r1 = setup()
		r1[2].Commitment = r1[2].Commitment[:len(r1[2].Commitment)-1]
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}

		p, r1 = setup()
		r1[2].Commitment = append(r1[2].Commitment, c.group.NewElement())
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errPolynomialLength.Error() {
			t.Fatalf("expected error %q, got %q", errPolynomialLength, err)
		}

		p, r1 = setup()
		r1[2].Commitment[0] = nil
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}

		p, r1 = setup()
		r1[2].Commitment[1] = testOtherGroup(c.group).Base()
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errCommitmentWrongGroup.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentWrongGroup, err)
		}

		p, r1 = setup()
		r1[2].Commitment[0] = c.group.NewElement()
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errCommitmentIdentityElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentIdentityElement, err)
		}

		p, r1 = setup()
		r1[2].Commitment[c.threshold-1] = c.group.NewElement()
		if _, err := p[0].Continue(r1); err == nil || err.Error() != errCommitmentIdentityElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentIdentityElement, err)
		}
	})
}

func TestParticipant_Continue_AllowsInteriorIdentityCommitment(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p := c.makeParticipantsWithZeroInteriorCoeff(t, 3)
		r1 := c.runRound1(p)

		if !r1[2].Commitment[1].IsIdentity() {
			t.Fatal("expected interior identity commitment")
		}

		if _, err := p[0].Continue(r1); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParticipant_Finalize_Bad_Round1DataElements(t *testing.T) {
	errRound1DataElements := errors.New("invalid number of expected round 1 data packets")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		shortR1 := r1[:int(c.threshold)]
		longR1 := append(append([]*dkg.Round1Data{}, r1...), r1[2])

		for _, participant := range p {
			if _, err := participant.Finalize(shortR1, r2[participant.Identifier]); err == nil ||
				err.Error() != errRound1DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
			}

			if _, err := participant.Finalize(longR1, r2[participant.Identifier]); err == nil ||
				err.Error() != errRound1DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound1DataElements, err)
			}
		}
	})
}

func TestParticipant_Finalize_Bad_Round1SenderIdentifier(t *testing.T) {
	errParticipantIDZero := errors.New("identifier is 0")
	errRound1NilPackage := errors.New("round 1 data packet is nil")
	errRound1MissingPackage := errors.New("missing round 1 package from participant")
	errRound1DuplicateSender := errors.New("duplicate round 1 package from participant")

	testAllCases(t, func(c *testCase) {
		setup := func() ([]*dkg.Participant, []*dkg.Round1Data, map[uint16][]*dkg.Round2Data) {
			p := c.makeParticipants(t)
			r1 := c.runRound1(p)
			return p, r1, c.runRound2(t, p, r1)
		}

		p, r1, r2 := setup()
		r1[2] = nil
		_, err := p[0].Finalize(r1, r2[p[0].Identifier])
		requireErrorString(t, err, errRound1NilPackage.Error())

		p, r1, r2 = setup()
		r1[2].SenderIdentifier = 0
		_, err = p[0].Finalize(r1, r2[p[0].Identifier])
		requireErrorString(t, err, errParticipantIDZero.Error())

		p, r1, r2 = setup()
		r1[2].SenderIdentifier = c.maxParticipants + 1
		_, err = p[0].Finalize(r1, r2[p[0].Identifier])
		requireErrorString(
			t,
			err,
			fmt.Sprintf("identifier is above authorized range [1:%d]: %d", c.maxParticipants, c.maxParticipants+1),
		)

		p, r1, r2 = setup()
		r1[3].SenderIdentifier = r1[2].SenderIdentifier
		_, err = p[0].Finalize(r1, r2[p[0].Identifier])
		requireErrorString(t, err, errRound1DuplicateSender.Error()+": 3")

		p, r1, r2 = setup()
		_, err = p[0].Finalize(r1[:int(c.maxParticipants-1)], r2[p[0].Identifier])
		requireErrorString(t, err, errRound1MissingPackage.Error()+": 5")
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
			d := append(append([]*dkg.Round2Data{}, r2[participant.Identifier]...), r2[participant.Identifier][0])
			if _, err := participant.Finalize(r1, d); err == nil || err.Error() != errRound2DataElements.Error() {
				t.Fatalf("expected error %q, got %q", errRound2DataElements, err)
			}
		}
	})
}

func TestParticipant_Finalize_Bad_Round2SenderIdentifier(t *testing.T) {
	errParticipantIDZero := errors.New("identifier is 0")
	errRound2NilPackage := errors.New("round 2 data packet is nil")
	errRound2DuplicateSender := errors.New("duplicate round 2 package from participant")

	testAllCases(t, func(c *testCase) {
		setup := func() ([]*dkg.Participant, []*dkg.Round1Data, []*dkg.Round2Data) {
			p := c.makeParticipants(t)
			r1 := c.runRound1(p)
			r2 := c.runRound2(t, p, r1)
			return p, r1, r2[p[0].Identifier]
		}

		p, r1, d := setup()
		d[2] = nil
		_, err := p[0].Finalize(r1, d)
		requireErrorString(t, err, errRound2NilPackage.Error())

		p, r1, d = setup()
		d[2].SenderIdentifier = 0
		_, err = p[0].Finalize(r1, d)
		requireErrorString(t, err, errParticipantIDZero.Error())

		p, r1, d = setup()
		d[2].SenderIdentifier = c.maxParticipants + 1
		_, err = p[0].Finalize(r1, d)
		requireErrorString(
			t,
			err,
			fmt.Sprintf("identifier is above authorized range [1:%d]: %d", c.maxParticipants, c.maxParticipants+1),
		)

		p, r1, d = setup()
		d[2].SenderIdentifier = d[3].SenderIdentifier
		_, err = p[0].Finalize(r1, d)
		requireErrorString(t, err, errRound2DuplicateSender.Error()+": 5")
	})
}

func TestParticipant_Finalize_Bad_Round2SecretShare(t *testing.T) {
	errSecretShareNil := errors.New("secret share is nil")
	errSecretShareWrongGroup := errors.New("secret share has incompatible EC group")

	testAllCases(t, func(c *testCase) {
		setup := func() ([]*dkg.Participant, []*dkg.Round1Data, []*dkg.Round2Data) {
			p := c.makeParticipants(t)
			r1 := c.runRound1(p)
			r2 := c.runRound2(t, p, r1)
			return p, r1, r2[p[0].Identifier]
		}

		p, r1, d := setup()
		sender := d[2].SenderIdentifier
		d[2].SecretShare = nil
		_, err := p[0].Finalize(r1, d)
		requireErrorString(t, err, fmt.Sprintf("%s: %d", errSecretShareNil, sender))

		p, r1, d = setup()
		sender = d[2].SenderIdentifier
		d[2].SecretShare = testOtherGroup(c.group).NewScalar().Random()
		_, err = p[0].Finalize(r1, d)
		requireErrorString(t, err, fmt.Sprintf("%s: %d", errSecretShareWrongGroup, sender))
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
	errRound1MissingPackage := errors.New("missing round 1 package from participant")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// r2 package sender is not in r1 data set
		d := r2[p[4].Identifier]

		expectedError := errRound1MissingPackage.Error() + ": 1"
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
	errRound1CommitmentMismatch := errors.New("round 1 commitment does not match verified commitment")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		// some commitment has a nil element
		r1[3].Commitment[1] = nil
		d := r2[p[0].Identifier]
		expectedError := errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentWrongGroup(t *testing.T) {
	errRound1CommitmentMismatch := errors.New("round 1 commitment does not match verified commitment")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		r1[3].Commitment[1] = testOtherGroup(c.group).Base()
		d := r2[p[0].Identifier]
		expectedError := errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentLength(t *testing.T) {
	errRound1CommitmentMismatch := errors.New("round 1 commitment does not match verified commitment")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		r1[3].Commitment = r1[3].Commitment[:len(r1[3].Commitment)-1]
		d := r2[p[0].Identifier]
		expectedError := errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r2 = c.runRound2(t, p, r1)

		r1[3].Commitment = append(r1[3].Commitment, c.group.NewElement())
		d = r2[p[0].Identifier]
		expectedError = errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentIdentityElement(t *testing.T) {
	errRound1CommitmentMismatch := errors.New("round 1 commitment does not match verified commitment")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		r1[3].Commitment[0] = c.group.NewElement()
		d := r2[p[0].Identifier]
		expectedError := errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r2 = c.runRound2(t, p, r1)

		r1[3].Commitment[c.threshold-1] = c.group.NewElement()
		d = r2[p[0].Identifier]
		expectedError = errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentEmpty(t *testing.T) {
	errRound1CommitmentMismatch := errors.New("round 1 commitment does not match verified commitment")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)

		// some commitment is nil or empty
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)
		d := r2[p[0].Identifier]

		r1[3].Commitment = nil
		expectedError := errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}

		r1[3].Commitment = []*ecc.Element{}
		expectedError = errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}
	})
}

func TestParticipant_Finalize_Bad_CommitmentMalformedElement(t *testing.T) {
	errRound1CommitmentMismatch := errors.New("round 1 commitment does not match verified commitment")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		validCommitment := cloneRound1(t, r1[3]).Commitment
		r1[3].Commitment[1] = new(ecc.Element)

		d := r2[p[0].Identifier]
		expectedError := errRound1CommitmentMismatch.Error() + ": 4"
		if _, err := p[0].Finalize(r1, d); err == nil || err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err)
		}

		r1[3].Commitment = validCommitment
		if _, err := p[0].Finalize(r1, d); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParticipant_Finalize_AllowsInteriorIdentityCommitment(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p := c.makeParticipantsWithZeroInteriorCoeff(t, 3)
		r1 := c.runRound1(p)

		if !r1[2].Commitment[1].IsIdentity() {
			t.Fatal("expected interior identity commitment")
		}

		r2 := c.runRound2(t, p, r1)
		c.finalize(t, p, r1, r2)
	})
}

func TestParticipant_Finalize_Bad_AggregateCommitmentHighestDegreeIdentity(t *testing.T) {
	expectedError := errors.New("aggregate commitment has identity commitment for the highest-degree coefficient")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipantsWithCancellingHighestDegreeCoeff(t)
		r1 := c.runRound1(p)
		r2 := c.runRound2(t, p, r1)

		_, err := p[0].Finalize(r1, r2[p[0].Identifier])
		requireErrorString(t, err, expectedError.Error())
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

func TestVerifyPublicKey_Bad_PubKeyWrongGroup(t *testing.T) {
	errPubKeyWrongGroup := errors.New("the provided public key has incompatible EC group")

	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		err := dkg.VerifyPublicKey(
			c.ciphersuite,
			keyshares[1].Identifier(),
			testOtherGroup(c.group).Base(),
			nil,
		)
		requireErrorString(t, err, errPubKeyWrongGroup.Error())
	})
}

func TestVerifyPublicKey_Bad_VerificationShareFailed(t *testing.T) {
	errVerificationShareFailed := errors.New("failed to compute correct verification share")

	testAllCases(t, func(c *testCase) {
		// id and pubkey not related
		_, r1, _, keyshares, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)

		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier(), keyshares[2].PublicKey(), commitments); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}

		// bad pubkey
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier(), c.group.NewElement(), commitments); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}

		// bad commitment
		commitments[4][2] = c.group.Base()
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier(), keyshares[1].PublicKey(), commitments); err == nil ||
			!strings.HasPrefix(err.Error(), errVerificationShareFailed.Error()) {
			t.Fatalf("expected error %q, got %q", errVerificationShareFailed, err)
		}
	})
}

func TestVerifyPublicKey_Bad_MissingCommitments(t *testing.T) {
	errMissingRound1Data := errors.New("missing commitment")

	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier(), keyshares[1].PublicKey(), nil); err == nil ||
			err.Error() != errMissingRound1Data.Error() {
			t.Fatalf("expected error %q, got %q", errMissingRound1Data, err)
		}
	})
}

func TestVerifyPublicKey_Bad_NoCommitment(t *testing.T) {
	errNoCommitment := errors.New("missing commitment")

	testAllCases(t, func(c *testCase) {
		_, r1, _, keyshares, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)

		commitments[3] = nil
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier(), keyshares[1].PublicKey(), commitments); err == nil ||
			err.Error() != errNoCommitment.Error() {
			t.Fatalf("expected error %q, got %q", errNoCommitment, err)
		}
	})
}

func TestVerifyPublicKey_Bad_CommitmentNilElement(t *testing.T) {
	errCommitmentNilElement := errors.New("commitment has nil element")

	testAllCases(t, func(c *testCase) {
		_, r1, _, keyshares, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)

		commitments[2][2] = nil
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier(), keyshares[1].PublicKey(), commitments); err == nil ||
			err.Error() != errCommitmentNilElement.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentNilElement, err)
		}
	})
}

func TestVerifyPublicKey_Bad_MalformedCommitment(t *testing.T) {
	errCommitmentWrongGroup := errors.New("commitment element has incompatible EC group")

	testAllCases(t, func(c *testCase) {
		_, r1, _, keyshares, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)

		commitments[2][2] = new(ecc.Element)
		if err := dkg.VerifyPublicKey(c.ciphersuite, keyshares[1].Identifier(), keyshares[1].PublicKey(), commitments); err == nil ||
			err.Error() != errCommitmentWrongGroup.Error() {
			t.Fatalf("expected error %q, got %q", errCommitmentWrongGroup, err)
		}
	})
}

func TestVSSCommitmentsFromRegistry(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, registry := completeDKG(t, c)
		commitments := dkg.VSSCommitmentsFromRegistry(registry)
		if len(commitments) != 1 {
			t.Fatalf("expected one aggregate commitment, got %d", len(commitments))
		}

		for _, keyshare := range keyshares {
			if err := dkg.VerifyPublicKey(c.ciphersuite, keyshare.Identifier(), keyshare.PublicKey(), commitments); err != nil {
				t.Fatal(err)
			}
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

func TestComputeParticipantPublicKey_Bad_IDZero(t *testing.T) {
	errParticipantIDZero := errors.New("identifier is 0")

	testAllCases(t, func(c *testCase) {
		_, r1, _, _, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)

		_, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 0, commitments)
		requireErrorString(t, err, errParticipantIDZero.Error())
	})
}

func TestComputeParticipantPublicKey_Bad_MissingRound1Data(t *testing.T) {
	errMissingRound1Data := errors.New("missing commitment")

	testAllCases(t, func(c *testCase) {
		// nil r1 data
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, nil); err == nil ||
			err.Error() != errMissingRound1Data.Error() {
			t.Fatalf("expected error %q got %q", errMissingRound1Data, err)
		}
	})
}

func TestComputeParticipantPublicKey_Bad_NoCommitment(t *testing.T) {
	errNoCommitment := errors.New("missing commitment")

	testAllCases(t, func(c *testCase) {
		_, r1, _, _, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)

		// missing commitment
		commitments[3] = nil
		if _, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, commitments); err == nil ||
			err.Error() != errNoCommitment.Error() {
			t.Fatalf("expected error %q, got %q", errNoCommitment, err)
		}
	})
}

func TestComputeParticipantPublicKey_Bad_CommitmentPolicy(t *testing.T) {
	errPolynomialLength := errors.New("invalid polynomial length")
	errCommitmentIdentityElement := errors.New("commitment has identity element")
	errCommitmentWrongGroup := errors.New("commitment element has incompatible EC group")

	testAllCases(t, func(c *testCase) {
		_, r1, _, _, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)
		commitments[2] = commitments[2][:len(commitments[2])-1]
		_, err := dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, commitments)
		requireErrorString(t, err, errPolynomialLength.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2][1] = testOtherGroup(c.group).Base()
		_, err = dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, commitments)
		requireErrorString(t, err, errCommitmentWrongGroup.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2][0] = c.group.NewElement()
		_, err = dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, commitments)
		requireErrorString(t, err, errCommitmentIdentityElement.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2][c.threshold-1] = c.group.NewElement()
		_, err = dkg.ComputeParticipantPublicKey(c.ciphersuite, 1, commitments)
		requireErrorString(t, err, errCommitmentIdentityElement.Error())
	})
}

func TestComputeParticipantPublicKey_Bad_CommitmentNilElement(t *testing.T) {
	errCommitmentNilElement := errors.New("commitment has nil element")

	testAllCases(t, func(c *testCase) {
		_, r1, _, _, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)

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

func TestVerificationKeyFromRound1_Bad_Round1Data(t *testing.T) {
	errParticipantIDZero := errors.New("identifier is 0")
	errRound1DataElements := errors.New("invalid number of expected round 1 data packets")
	errRound1NilPackage := errors.New("round 1 data packet is nil")
	errRound1DuplicateSender := errors.New("duplicate round 1 package from participant")
	errMissingCommitment := errors.New("missing commitment")
	errPolynomialLength := errors.New("invalid polynomial length")
	errCommitmentIdentityElement := errors.New("commitment has identity element")
	errCommitmentWrongGroup := errors.New("commitment element has incompatible EC group")

	testAllCases(t, func(c *testCase) {
		_, err := dkg.VerificationKeyFromRound1(c.ciphersuite, nil)
		requireErrorString(t, err, errRound1DataElements.Error())

		p := c.makeParticipants(t)
		r1 := c.runRound1(p)
		r1[2] = nil
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errRound1NilPackage.Error())

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r1[2].SenderIdentifier = 0
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errParticipantIDZero.Error())

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r1[3].SenderIdentifier = r1[2].SenderIdentifier
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errRound1DuplicateSender.Error()+": 3")

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r1[2].Commitment = nil
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errMissingCommitment.Error())

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r1[2].Commitment = r1[2].Commitment[:len(r1[2].Commitment)-1]
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errPolynomialLength.Error())

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r1[2].Commitment[1] = testOtherGroup(c.group).Base()
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errCommitmentWrongGroup.Error())

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r1[2].Commitment[0] = c.group.NewElement()
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, "ABORT - invalid signature: participant 3")

		p = c.makeParticipants(t)
		r1 = c.runRound1(p)
		r1[2].Commitment[c.threshold-1] = c.group.NewElement()
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errCommitmentIdentityElement.Error())
	})
}

func TestVerificationKeyFromRound1_ProofValidation(t *testing.T) {
	errAbortInvalidSignature := errors.New("ABORT - invalid signature")

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		r1 := c.runRound1(p)

		if _, err := dkg.VerificationKeyFromRound1(c.ciphersuite, r1); err != nil {
			t.Fatal(err)
		}

		setup := func() []*dkg.Round1Data {
			participants := c.makeParticipants(t)
			return c.runRound1(participants)
		}

		r1 = setup()
		r1[2].ProofOfKnowledge.Clear()
		_, err := dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errAbortInvalidSignature.Error()+": participant 3")

		r1 = setup()
		r1[2].ProofOfKnowledge = nil
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errAbortInvalidSignature.Error()+": participant 3")

		r1 = setup()
		r1[2].ProofOfKnowledge.R = c.group.NewElement()
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errAbortInvalidSignature.Error()+": participant 3")

		r1 = setup()
		r1[2].ProofOfKnowledge.Z = c.group.NewScalar().Zero()
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errAbortInvalidSignature.Error()+": participant 3")

		r1 = setup()
		r1[2].ProofOfKnowledge.R = new(ecc.Element)
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errAbortInvalidSignature.Error()+": participant 3")

		r1 = setup()
		r1[2].ProofOfKnowledge.Z = new(ecc.Scalar)
		_, err = dkg.VerificationKeyFromRound1(c.ciphersuite, r1)
		requireErrorString(t, err, errAbortInvalidSignature.Error()+": participant 3")
	})
}

func TestVerificationKeyFromCommitments_Bad_CommitmentPolicy(t *testing.T) {
	errMissingCommitment := errors.New("missing commitment")
	errPolynomialLength := errors.New("invalid polynomial length")
	errCommitmentNilElement := errors.New("commitment has nil element")
	errCommitmentIdentityElement := errors.New("commitment has identity element")
	errCommitmentWrongGroup := errors.New("commitment element has incompatible EC group")

	testAllCases(t, func(c *testCase) {
		_, err := dkg.VerificationKeyFromCommitments(c.ciphersuite, nil)
		requireErrorString(t, err, errMissingCommitment.Error())

		_, r1, _, _, _ := completeDKG(t, c)
		commitments := commitmentsFromRound1(r1)
		commitments[2] = nil
		_, err = dkg.VerificationKeyFromCommitments(c.ciphersuite, commitments)
		requireErrorString(t, err, errMissingCommitment.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2] = commitments[2][:len(commitments[2])-1]
		_, err = dkg.VerificationKeyFromCommitments(c.ciphersuite, commitments)
		requireErrorString(t, err, errPolynomialLength.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2][1] = nil
		_, err = dkg.VerificationKeyFromCommitments(c.ciphersuite, commitments)
		requireErrorString(t, err, errCommitmentNilElement.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2][1] = testOtherGroup(c.group).Base()
		_, err = dkg.VerificationKeyFromCommitments(c.ciphersuite, commitments)
		requireErrorString(t, err, errCommitmentWrongGroup.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2][0] = c.group.NewElement()
		_, err = dkg.VerificationKeyFromCommitments(c.ciphersuite, commitments)
		requireErrorString(t, err, errCommitmentIdentityElement.Error())

		_, r1, _, _, _ = completeDKG(t, c)
		commitments = commitmentsFromRound1(r1)
		commitments[2][c.threshold-1] = c.group.NewElement()
		_, err = dkg.VerificationKeyFromCommitments(c.ciphersuite, commitments)
		requireErrorString(t, err, errCommitmentIdentityElement.Error())
	})
}

func TestVerificationKeyFromCommitments_AllowsInteriorIdentityCommitment(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p := c.makeParticipantsWithZeroInteriorCoeff(t, 3)
		r1 := c.runRound1(p)
		commitments := commitmentsFromRound1(r1)

		if _, err := dkg.VerificationKeyFromCommitments(c.ciphersuite, commitments); err != nil {
			t.Fatal(err)
		}
	})
}

func TestVerificationKey_BadCipher(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")

	if _, err := dkg.VerificationKeyFromRound1(dkg.Ciphersuite(2), nil); err == nil ||
		err.Error() != errInvalidCiphersuite.Error() {
		t.Fatalf("expected %q, got %q", errInvalidCiphersuite, err)
	}

	if _, err := dkg.VerificationKeyFromCommitments(dkg.Ciphersuite(2), nil); err == nil ||
		err.Error() != errInvalidCiphersuite.Error() {
		t.Fatalf("expected %q, got %q", errInvalidCiphersuite, err)
	}
}
