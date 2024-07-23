// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg_test

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/dkg"
)

type RoundData interface {
	Encode() []byte
	Decode([]byte) error
}

func testByteEncoding(t *testing.T, r, bDec RoundData) {
	bEnc := r.Encode()

	if err := bDec.Decode(bEnc); err != nil {
		t.Fatal(err)
	}
}

func testJSON(t *testing.T, r, jsonDec any) {
	jsonEnc, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}

	if err = json.Unmarshal(jsonEnc, jsonDec); err != nil {
		t.Fatal(err)
	}
}

func compareR1Data(t *testing.T, d1, d2 *dkg.Round1Data) {
	if d1.Group != d2.Group {
		t.Fatal("expected same group")
	}

	if d1.SenderIdentifier != d2.SenderIdentifier {
		t.Fatal("expected same id")
	}

	if d1.ProofOfKnowledge.R.Equal(d2.ProofOfKnowledge.R) != 1 {
		t.Fatal("expected same r proof")
	}

	if d1.ProofOfKnowledge.Z.Equal(d2.ProofOfKnowledge.Z) != 1 {
		t.Fatal("expected same z proof")
	}

	if len(d1.Commitment) != len(d2.Commitment) {
		t.Fatal("different lengths of commitment")
	}

	for i, d := range d1.Commitment {
		if d.Equal(d2.Commitment[i]) != 1 {
			t.Fatal("expected same commitment")
		}
	}
}

func compareR2Data(t *testing.T, d1, d2 *dkg.Round2Data) {
	if d1.Group != d2.Group {
		t.Fatal("expected same group")
	}

	if d1.SenderIdentifier != d2.SenderIdentifier {
		t.Fatal("expected same sender id")
	}

	if d1.RecipientIdentifier != d2.RecipientIdentifier {
		t.Fatal("expected same receiver id")
	}

	if d1.SecretShare.Equal(d2.SecretShare) != 1 {
		t.Fatal("expected same secret share")
	}
}

func testR1Encoding(t *testing.T, p *dkg.Participant, r *dkg.Round1Data) {
	// Test byte encoding
	bDec := p.NewRound1Data()
	testByteEncoding(t, r, bDec)
	compareR1Data(t, r, bDec)

	// Test JSON encoding
	jsonDec := p.NewRound1Data()
	testJSON(t, r, jsonDec)
	compareR1Data(t, r, jsonDec)
}

func testR2Encoding(t *testing.T, p *dkg.Participant, d map[uint64]*dkg.Round2Data) {
	for _, r := range d {
		// Test byte encoding
		bDec := p.NewRound2Data()
		testByteEncoding(t, r, bDec)
		compareR2Data(t, r, bDec)

		// Test JSON encoding
		jsonDec := p.NewRound2Data()
		testJSON(t, r, jsonDec)
		compareR2Data(t, r, jsonDec)
	}
}

func Test_Encoding(t *testing.T) {
	c := dkg.Ristretto255Sha512
	maxSigners := uint(3)
	threshold := uint(2)

	p1, _ := c.NewParticipant(1, maxSigners, threshold)
	p2, _ := c.NewParticipant(2, maxSigners, threshold)
	p3, _ := c.NewParticipant(3, maxSigners, threshold)

	r1P1 := p1.Start()
	r1P2 := p2.Start()
	r1P3 := p3.Start()

	testR1Encoding(t, p2, r1P1)
	testR1Encoding(t, p1, r1P2)
	testR1Encoding(t, p1, r1P3)

	p1r1 := []*dkg.Round1Data{r1P2, r1P3}
	p2r1 := []*dkg.Round1Data{r1P1, r1P3}
	p3r1 := []*dkg.Round1Data{r1P1, r1P2}

	r2P1, err := p1.Continue(p1r1)
	if err != nil {
		t.Fatal(err)
	}

	r2P2, err := p2.Continue(p2r1)
	if err != nil {
		t.Fatal(err)
	}

	r2P3, err := p3.Continue(p3r1)
	if err != nil {
		t.Fatal(err)
	}

	testR2Encoding(t, p2, r2P1)
	testR2Encoding(t, p1, r2P2)
	testR2Encoding(t, p1, r2P3)

	p1r2 := make([]*dkg.Round2Data, 0, maxSigners-1)
	p1r2 = append(p1r2, r2P2[p1.Identifier])
	p1r2 = append(p1r2, r2P3[p1.Identifier])

	p2r2 := make([]*dkg.Round2Data, 0, maxSigners-1)
	p2r2 = append(p2r2, r2P1[p2.Identifier])
	p2r2 = append(p2r2, r2P3[p2.Identifier])

	p3r2 := make([]*dkg.Round2Data, 0, maxSigners-1)
	p3r2 = append(p3r2, r2P1[p3.Identifier])
	p3r2 = append(p3r2, r2P2[p3.Identifier])

	if _, err = p1.Finalize(p1r1, p1r2); err != nil {
		t.Fatal(err)
	}

	if _, err = p2.Finalize(p2r1, p2r2); err != nil {
		t.Fatal(err)
	}

	if _, err = p3.Finalize(p3r1, p3r2); err != nil {
		t.Fatal(err)
	}
}

func TestParticipant_NewRound1Data(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p, _ := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold)
		d := p.NewRound1Data()

		if d.Group != c.group {
			t.Fatal()
		}

		if d.ProofOfKnowledge == nil {
			t.Fatal()
		}

		if d.ProofOfKnowledge.R == nil || !d.ProofOfKnowledge.R.IsIdentity() {
			t.Fatal()
		}

		if d.ProofOfKnowledge.Z == nil || !d.ProofOfKnowledge.Z.IsZero() {
			t.Fatal()
		}

		if uint(len(d.Commitment)) != c.threshold {
			t.Fatal()
		}

		for _, com := range d.Commitment {
			if com == nil || !com.IsIdentity() {
				t.Fatal()
			}
		}
	})
}

func TestParticipant_NewRound2Data(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p, _ := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold)
		d := p.NewRound2Data()

		if d.Group != c.group {
			t.Fatal()
		}

		if d.SecretShare == nil || !d.SecretShare.IsZero() {
			t.Fatal()
		}

		if d.SenderIdentifier != 0 || d.RecipientIdentifier != 0 {
			t.Fatal()
		}
	})
}

func TestRound1_Decode_Fail(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")
	errDecodeNoMessage := errors.New("no data to decode")
	errDecodeInvalidLength := errors.New("invalid encoding length")
	errDecodeProofR := errors.New("invalid encoding of R proof")
	errDecodeProofZ := errors.New("invalid encoding of z proof")
	errDecodeCommitment := errors.New("invalid encoding of commitment")

	testAllCases(t, func(c *testCase) {
		p, _ := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold)
		r1 := p.NewRound1Data()

		// nil or len = 0
		if err := r1.Decode(nil); err == nil || err.Error() != errDecodeNoMessage.Error() {
			t.Fatalf("expected error %q, got %q", errDecodeNoMessage, err)
		}

		if err := r1.Decode([]byte{}); err == nil || err.Error() != errDecodeNoMessage.Error() {
			t.Fatalf("expected error %q, got %q", errDecodeNoMessage, err)
		}

		// invalid ciphersuite
		if err := r1.Decode([]byte{2}); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error %q, got %q", errInvalidCiphersuite, err)
		}

		badC := dkg.Ristretto255Sha512
		if c.ciphersuite == dkg.Ristretto255Sha512 {
			badC = dkg.P256Sha256
		}
		if err := r1.Decode([]byte{byte(badC)}); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error %q, got %q", errInvalidCiphersuite, err)
		}

		// invalid length: to low, too high
		expectedSize := 1 + 8 + c.group.ElementLength() + c.group.ScalarLength() + int(
			c.threshold,
		)*c.group.ElementLength()
		data := make([]byte, expectedSize+1)
		data[0] = byte(c.ciphersuite)

		expected := fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, len(data))
		if err := r1.Decode(data); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		expected = fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, expectedSize-1)
		if err := r1.Decode(data[:expectedSize-1]); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// proof: bad r
		data = make([]byte, 9, expectedSize)
		data[0] = byte(c.group)
		binary.LittleEndian.PutUint64(data[1:9], 1)
		data = append(data, badElement(t, c.group)...)
		data = append(data, badScalar(t, c.group)...)
		data = append(data, make([]byte, expectedSize-len(data))...) // fill the tail

		if err := r1.Decode(data); err == nil || !strings.HasPrefix(err.Error(), errDecodeProofR.Error()) {
			t.Fatalf("expected error %q, got %q", errDecodeProofR, err)
		}

		// proof: bad z
		data = make([]byte, 9, expectedSize)
		data[0] = byte(c.group)
		binary.LittleEndian.PutUint64(data[1:9], 256)
		data = append(data, c.group.Base().Encode()...)
		data = append(data, badScalar(t, c.group)...)
		data = append(data, make([]byte, expectedSize-len(data))...) // fill the tail

		if err := r1.Decode(data); err == nil || !strings.HasPrefix(err.Error(), errDecodeProofZ.Error()) {
			t.Fatalf("expected error %q, got %q", errDecodeProofZ, err)
		}

		// commitment: some error in one of the elements
		data = make([]byte, 9, expectedSize)
		data[0] = byte(c.group)
		binary.LittleEndian.PutUint64(data[1:9], 1)
		data = append(data, c.group.Base().Encode()...)
		data = append(data, c.group.NewScalar().Random().Encode()...)
		for range c.threshold {
			data = append(data, badElement(t, c.group)...)
		}

		if err := r1.Decode(data); err == nil || !strings.HasPrefix(err.Error(), errDecodeCommitment.Error()) {
			t.Fatalf("expected error %q, got %q", errDecodeCommitment, err)
		}
	})
}

func badScalar(t *testing.T, g group.Group) []byte {
	order, ok := new(big.Int).SetString(g.Order(), 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, g.Order())
	}

	encoded := make([]byte, g.ScalarLength())
	order.FillBytes(encoded)

	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(encoded)
	}

	return encoded
}

func badElement(t *testing.T, g group.Group) []byte {
	order, ok := new(big.Int).SetString(g.Order(), 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, g.Order())
	}

	encoded := make([]byte, g.ElementLength())
	order.FillBytes(encoded)

	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(encoded)
	}

	return encoded
}

func TestBadScalar(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		if err := c.group.NewScalar().Decode(badScalar(t, c.group)); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestBadElement(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		if err := c.group.NewElement().Decode(badElement(t, c.group)); err == nil {
			t.Error("expected error")
		}
	})
}

func TestRound2_Decode_Fail(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")
	errDecodeNoMessage := errors.New("no data to decode")
	errDecodeInvalidLength := errors.New("invalid encoding length")
	errDecodeSecretShare := errors.New("invalid encoding of secret share")

	testAllCases(t, func(c *testCase) {
		p, _ := c.ciphersuite.NewParticipant(1, c.maxParticipants, c.threshold)
		r2 := p.NewRound2Data()

		// nil or len = 0
		if err := r2.Decode(nil); err == nil || err.Error() != errDecodeNoMessage.Error() {
			t.Fatalf("expected error %q, got %q", errDecodeNoMessage, err)
		}

		if err := r2.Decode([]byte{}); err == nil || err.Error() != errDecodeNoMessage.Error() {
			t.Fatalf("expected error %q, got %q", errDecodeNoMessage, err)
		}

		// invalid ciphersuite
		if err := r2.Decode([]byte{2}); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error %q, got %q", errInvalidCiphersuite, err)
		}

		badC := dkg.Ristretto255Sha512
		if c.ciphersuite == dkg.Ristretto255Sha512 {
			badC = dkg.P256Sha256
		}
		if err := r2.Decode([]byte{byte(badC)}); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error %q, got %q", errInvalidCiphersuite, err)
		}

		// invalid length: too short, too long
		expectedSize := 1 + 16 + c.group.ScalarLength()
		data := make([]byte, expectedSize+1)
		data[0] = byte(c.ciphersuite)

		expected := fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, len(data))
		if err := r2.Decode(data); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		expected = fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, expectedSize-1)
		if err := r2.Decode(data[:expectedSize-1]); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// bad share encoding
		data = make([]byte, 17, expectedSize)
		data[0] = byte(c.group)
		binary.LittleEndian.PutUint64(data[1:9], 1)
		binary.LittleEndian.PutUint64(data[9:17], 2)
		data = append(data, badScalar(t, c.group)...)

		if err := r2.Decode(data); err == nil || !strings.HasPrefix(err.Error(), errDecodeSecretShare.Error()) {
			t.Fatalf("expected error %q, got %q", errDecodeSecretShare, err)
		}
	})
}

func TestKeyShare_Encoding(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		k := keyshares[0]
		e := k.Encode()

		d := new(dkg.KeyShare)
		if err := d.Decode(e); err != nil {
			t.Fatal(err)
		}

		if err := compareKeyShares(k, d); err != nil {
			t.Fatal(err)
		}
	})
}

func TestKeyShare_EncodingJSON(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		k := keyshares[0]
		e, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}

		d := new(dkg.KeyShare)
		if err := json.Unmarshal(e, d); err != nil {
			t.Fatal(err)
		}

		if err := compareKeyShares(k, d); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPublicKeyShare_Encoding(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		pks := keyshares[0].Public()
		e := pks.Encode()

		d := new(dkg.PublicKeyShare)
		if err := d.Decode(e); err != nil {
			t.Fatal(err)
		}

		if err := comparePublicKeyShare(pks, d); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPublicKeyShare_Encoding_Bad(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		pks := keyshares[0].Public()
		e := pks.Encode()
		e[0] = 2

		d := new(dkg.PublicKeyShare)
		if err := d.Decode(e); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestPublicKeyShare_JSON(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		pks := keyshares[0].Public()
		e, err := json.Marshal(pks)
		if err != nil {
			t.Fatal(err)
		}

		d := new(dkg.PublicKeyShare)
		if err := json.Unmarshal(e, d); err != nil {
			t.Fatal(err)
		}

		if err := comparePublicKeyShare(pks, d); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPublicKeyShare_JSON_Bad(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, keyshares, _ := completeDKG(t, c)

		pks := keyshares[0].Public()
		pks.Group = 0

		e, err := json.Marshal(pks)
		if err != nil {
			t.Fatal(err)
		}

		d := new(dkg.PublicKeyShare)
		if err := json.Unmarshal(e, d); err == nil {
			t.Fatal("expected error")
		}
	})
}

func compareKeyShares(s1, s2 *dkg.KeyShare) error {
	if s1.Secret.Equal(s2.Secret) != 1 {
		return fmt.Errorf("Expected equality on Secret:\n\t%s\n\t%s\n", s1.Secret.Hex(), s2.Secret.Hex())
	}

	if s1.GroupPublicKey.Equal(s2.GroupPublicKey) != 1 {
		return fmt.Errorf(
			"Expected equality on GroupPublicKey:\n\t%s\n\t%s\n",
			s1.GroupPublicKey.Hex(),
			s2.GroupPublicKey.Hex(),
		)
	}

	return comparePublicKeyShare(s1.Public(), s2.Public())
}

func comparePublicKeyShare(p1, p2 *dkg.PublicKeyShare) error {
	if p1.PublicKey.Equal(p2.PublicKey) != 1 {
		return fmt.Errorf("Expected equality on PublicKey:\n\t%s\n\t%s\n", p1.PublicKey.Hex(), p2.PublicKey.Hex())
	}

	if p1.ID != p2.ID {
		return fmt.Errorf("Expected equality on ID:\n\t%d\n\t%d\n", p1.ID, p2.ID)
	}

	if p1.Group != p2.Group {
		return fmt.Errorf("Expected equality on Group:\n\t%v\n\t%v\n", p1.Group, p2.Group)
	}

	if len(p1.Commitment) != len(p2.Commitment) {
		return fmt.Errorf(
			"Expected equality on Commitment length:\n\t%d\n\t%d\n",
			len(p1.Commitment),
			len(p1.Commitment),
		)
	}

	for i := range p1.Commitment {
		if p1.Commitment[i].Equal(p2.Commitment[i]) != 1 {
			return fmt.Errorf(
				"Expected equality on Commitment %d:\n\t%s\n\t%s\n",
				i,
				p1.Commitment[i].Hex(),
				p1.Commitment[i].Hex(),
			)
		}
	}

	return nil
}

func compareRegistries(r1, r2 *dkg.PublicKeyShareRegistry) error {
	if r1.Ciphersuite != r2.Ciphersuite || r1.Total != r2.Total || r1.Threshold != r2.Threshold {
		return errors.New("wrong header")
	}

	if r1.GroupPublicKey.Equal(r2.GroupPublicKey) != 1 {
		return errors.New("wrong gpk")
	}

	if len(r1.PublicKeyShares) != len(r2.PublicKeyShares) {
		return errors.New("wrong pks length")
	}

	for i, pks := range r1.PublicKeyShares {
		pks2 := r2.PublicKeyShares[i]
		if err := comparePublicKeyShare(pks, pks2); err != nil {
			return err
		}
	}

	return nil
}

func TestRegistry_Encoding(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, _, registry := completeDKG(t, c)

		// Bytes
		b := registry.Encode()
		r2 := new(dkg.PublicKeyShareRegistry)

		if err := r2.Decode(b); err != nil {
			t.Fatal(err)
		}

		if err := compareRegistries(registry, r2); err != nil {
			t.Fatal(err)
		}

		// JSON
		j, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}

		r2 = new(dkg.PublicKeyShareRegistry)
		if err := json.Unmarshal(j, r2); err != nil {
			t.Fatal(err)
		}

		if err = compareRegistries(registry, r2); err != nil {
			t.Fatal(err)
		}
	})
}

func getBadNistElement(t *testing.T, g group.Group) []byte {
	element := make([]byte, g.ElementLength())
	if _, err := rand.Read(element); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}
	// detag compression
	element[0] = 4

	// test if invalid compression is detected
	err := g.NewElement().Decode(element)
	if err == nil {
		t.Errorf("detagged compressed point did not yield an error for group %s", g)
	}

	return element
}

func getBadRistrettoElement() []byte {
	a := "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBadEdwardsElement() []byte {
	a := "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBadElement(t *testing.T, g group.Group) []byte {
	switch g {
	case group.Ristretto255Sha512:
		return getBadRistrettoElement()
	case group.Edwards25519Sha512:
		return getBadEdwardsElement()
	default:
		return getBadNistElement(t, g)
	}
}

func getBadScalar(g group.Group) []byte {
	order := g.Order()
	o, _ := new(big.Int).SetString(order, 0)
	o.Add(o, new(big.Int).SetInt64(10))
	out := make([]byte, g.ScalarLength())
	o.FillBytes(out)
	if g == group.Ristretto255Sha512 || g == group.Edwards25519Sha512 {
		slices.Reverse(out)
	}

	return out
}

func TestRegistry_Decode_Bad(t *testing.T) {
	errEncodingInvalidLength := errors.New("invalid encoding length")
	errInvalidCiphersuite := errors.New("invalid ciphersuite")
	errEncodingPKSDuplication := errors.New("multiple encoded public key shares with same ID")
	errEncodingInvalidJSONEncoding := errors.New("invalid JSON encoding")

	testAllCases(t, func(c *testCase) {
		_, _, _, _, registry := completeDKG(t, c)
		d := new(dkg.PublicKeyShareRegistry)
		badElement := getBadElement(t, c.group)

		// too short
		if err := d.Decode([]byte{1, 2, 3}); err == nil || err.Error() != errEncodingInvalidLength.Error() {
			t.Fatalf("expected error %q, got %q", errEncodingInvalidLength, err)
		}

		// invalid ciphersuite
		e := registry.Encode()
		e[0] = 2

		if err := d.Decode(e); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error %q, got %q", errInvalidCiphersuite, err)
		}

		// too short
		e = registry.Encode()
		l := len(e) - 5

		if err := d.Decode(e[:l]); err == nil || err.Error() != errEncodingInvalidLength.Error() {
			t.Fatalf("expected error %q, got %q", errEncodingInvalidLength, err)
		}

		// Decode: Bad public key
		e = registry.Encode()
		e = slices.Replace(e, 5, 5+c.group.ElementLength(), badElement...)
		expectedErrorPrefix := errors.New("invalid group public key encoding")
		if err := d.Decode(e); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
			t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
		}

		// Decode: a faulty public key share, with a wrong group
		e = registry.Encode()
		e[5+c.group.ElementLength()] = 2
		expectedErrorPrefix = errors.New("could not decode public key share")
		if err := d.Decode(e); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
			t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
		}

		// Decode: double entry, replacing the 2nd share with the third
		pks1 := registry.PublicKeyShares[1].Encode()
		pks2 := registry.PublicKeyShares[2].Encode()
		pks3 := registry.PublicKeyShares[3].Encode()
		start := 5 + c.group.ElementLength() + len(pks1)
		end := start + len(pks2)
		e = registry.Encode()

		// Since we're using a map, we're not ensured to have the same order in encoding. So we force
		// two consecutive writes.
		e = slices.Replace(e, start, end, pks3...)
		e = slices.Replace(e, end, end+len(pks3), pks3...)

		if err := d.Decode(e); err == nil || err.Error() != errEncodingPKSDuplication.Error() {
			t.Fatalf("expected error %q, got %q", errEncodingPKSDuplication, err)
		}

		// JSON: bad json
		data, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}

		data = replaceStringInBytes(data, "\"ciphersuite\"", "bad")
		expectedErrorPrefix = errors.New("invalid character 'b' looking for beginning of object key string")

		if err = json.Unmarshal(data, d); err == nil || !strings.HasPrefix(err.Error(), expectedErrorPrefix.Error()) {
			t.Fatalf("expected error %q, got %q", expectedErrorPrefix, err)
		}

		// UnmarshallJSON: bad group
		data, err = json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}

		data = replaceStringInBytes(data, fmt.Sprintf("\"ciphersuite\":%d", registry.Ciphersuite), "\"ciphersuite\":70")
		if err = json.Unmarshal(data, d); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error %q, got %q", errInvalidCiphersuite, err)
		}

		// UnmarshallJSON: bad group
		data, err = json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}

		data = replaceStringInBytes(data, fmt.Sprintf("\"ciphersuite\":%d", c.group), "\"ciphersuite\":17")
		if err = json.Unmarshal(data, d); err == nil || err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected error %q, got %q", errInvalidCiphersuite, err)
		}

		// UnmarshallJSON: bad group encoding
		data, err = json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}

		data = replaceStringInBytes(data, fmt.Sprintf("\"ciphersuite\":%d", c.group), "\"ciphersuite\":-1")
		if err = json.Unmarshal(data, d); err == nil || err.Error() != errEncodingInvalidJSONEncoding.Error() {
			t.Fatalf("expected error %q, got %q", errEncodingInvalidJSONEncoding, err)
		}
	})
}

func replaceStringInBytes(data []byte, old, new string) []byte {
	s := string(data)
	s = strings.Replace(s, old, new, 1)

	return []byte(s)
}

func TestRegistry_JSON(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		_, _, _, _, registry := completeDKG(t, c)

		// JSON
		j, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}

		r2 := new(dkg.PublicKeyShareRegistry)
		if err := json.Unmarshal(j, r2); err != nil {
			t.Fatal(err)
		}

		if err = compareRegistries(registry, r2); err != nil {
			t.Fatal(err)
		}
	})
}
