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
	"testing"

	"github.com/bytemare/ecc"

	"github.com/bytemare/dkg"
)

func readHexScalar(t *testing.T, g ecc.Group, input string) *ecc.Scalar {
	s := g.NewScalar()
	if err := s.DecodeHex(input); err != nil {
		t.Fatal(err)
	}

	return s
}

func readHexElement(t *testing.T, g ecc.Group, input string) *ecc.Element {
	s := g.NewElement()
	if err := s.DecodeHex(input); err != nil {
		t.Fatal(err)
	}

	return s
}

func TestFrostGenerateZeroKnowledgeProof(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		id := c.zk.id
		k := readHexScalar(t, c.group, c.zk.k)
		sk := readHexScalar(t, c.group, c.zk.sk)
		pk := readHexElement(t, c.group, c.zk.pk)
		r := readHexElement(t, c.group, c.zk.r)
		z := readHexScalar(t, c.group, c.zk.z)

		s, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, k)
		if err != nil {
			t.Fatal(err)
		}

		if s == nil {
			t.Fatal()
		}

		if !r.Equal(s.R) {
			t.Fatal()
		}

		if !z.Equal(s.Z) {
			t.Fatal()
		}
	})
}

func TestFrostGenerateZeroKnowledgeProof_BadInputs(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		id := c.zk.id
		sk := readHexScalar(t, c.group, c.zk.sk)
		pk := readHexElement(t, c.group, c.zk.pk)
		nonce := readHexScalar(t, c.group, c.zk.k)

		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, 0, sk, pk, nonce); err == nil ||
			err.Error() != errors.New("identifier is 0").Error() {
			t.Fatalf("expected participant id error, got %q", err)
		}

		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, nil, pk, nonce); err == nil ||
			err.Error() != errors.New("the provided secret is nil").Error() {
			t.Fatalf("expected nil secret error, got %q", err)
		}

		badSecretGroup := testOtherGroup(c.group).NewScalar().Random()
		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, badSecretGroup, pk, nonce); err == nil ||
			err.Error() != errors.New("the provided secret has incompatible EC group").Error() {
			t.Fatalf("expected secret group error, got %q", err)
		}

		zeroSecret := c.group.NewScalar()
		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, zeroSecret, pk, nonce); err == nil ||
			err.Error() != errors.New("the provided secret is zero").Error() {
			t.Fatalf("expected zero secret error, got %q", err)
		}

		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, nil, nonce); err == nil ||
			err.Error() != errors.New("the provided public key is nil").Error() {
			t.Fatalf("expected nil public key error, got %q", err)
		}

		badPubKeyGroup := testOtherGroup(c.group).Base()
		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, badPubKeyGroup, nonce); err == nil ||
			err.Error() != errors.New("the provided public key has incompatible EC group").Error() {
			t.Fatalf("expected public key group error, got %q", err)
		}

		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, c.group.NewElement(), nonce); err == nil ||
			err.Error() != errors.New("the provided public key is identity").Error() {
			t.Fatalf("expected identity public key error, got %q", err)
		}

		mismatchedPK := c.group.Base().Multiply(c.group.NewScalar().Random())
		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, mismatchedPK, nonce); err == nil ||
			err.Error() != errors.New("the provided public key does not match the secret").Error() {
			t.Fatalf("expected mismatch error, got %q", err)
		}

		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, nil, nonce); err == nil ||
			err.Error() != errors.New("only one deterministic nonce is supported").Error() {
			t.Fatalf("expected multiple nonce error, got %q", err)
		}

		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, nil); err == nil ||
			err.Error() != errors.New("the provided nonce is nil").Error() {
			t.Fatalf("expected nil nonce error, got %q", err)
		}

		otherNonce := testOtherGroup(c.group).NewScalar().Random()
		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, otherNonce); err == nil ||
			err.Error() != errors.New("the provided nonce has incompatible EC group").Error() {
			t.Fatalf("expected nonce group error, got %q", err)
		}

		zeroNonce := c.group.NewScalar()
		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, zeroNonce); err == nil ||
			err.Error() != errors.New("the provided nonce is zero").Error() {
			t.Fatalf("expected zero nonce error, got %q", err)
		}
	})
}

func TestFrostGenerateZeroKnowledgeProof_DeterministicNonceNotMutated(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		id := c.zk.id
		nonce := readHexScalar(t, c.group, c.zk.k)
		nonceBefore := nonce.Copy()
		sk := readHexScalar(t, c.group, c.zk.sk)
		pk := readHexElement(t, c.group, c.zk.pk)

		if _, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, nonce); err != nil {
			t.Fatal(err)
		}

		if !nonce.Equal(nonceBefore) {
			t.Fatal("expected caller nonce to remain unchanged")
		}
	})
}

func TestFrostVerifyZeroKnowledgeProof(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		id := c.zk.id
		pk := readHexElement(t, c.group, c.zk.pk)
		s := &dkg.Signature{
			Group: c.group,
			R:     readHexElement(t, c.group, c.zk.r),
			Z:     readHexScalar(t, c.group, c.zk.z),
		}

		if ok, _ := dkg.FrostVerifyZeroKnowledgeProof(c.ciphersuite, id, pk, s); !ok {
			t.Fatal()
		}
	})
}

func TestFrostVerifyZeroKnowledgeProof_RejectsIdentityInputs(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		id := c.zk.id
		pk := readHexElement(t, c.group, c.zk.pk)
		proof := &dkg.Signature{
			Group: c.group,
			R:     readHexElement(t, c.group, c.zk.r),
			Z:     readHexScalar(t, c.group, c.zk.z),
		}

		if ok, err := dkg.FrostVerifyZeroKnowledgeProof(c.ciphersuite, 0, pk, proof); err == nil || ok {
			t.Fatal("expected zero participant id to be rejected")
		}

		proof.R = c.group.NewElement()
		if ok, err := dkg.FrostVerifyZeroKnowledgeProof(c.ciphersuite, id, pk, proof); err != nil || ok {
			t.Fatal("expected identity R to be rejected")
		}

		proof.R = readHexElement(t, c.group, c.zk.r)
		if ok, err := dkg.FrostVerifyZeroKnowledgeProof(c.ciphersuite, id, c.group.NewElement(), proof); err != nil ||
			ok {
			t.Fatal("expected identity pubkey to be rejected")
		}
	})
}

func TestFrostVerifyZeroKnowledgeProof_MalformedInputs(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		id := c.zk.id
		pk := readHexElement(t, c.group, c.zk.pk)
		proof := &dkg.Signature{
			Group: c.group,
			R:     new(ecc.Element),
			Z:     new(ecc.Scalar),
		}

		if has, err := hasPanic(func() {
			ok, err := dkg.FrostVerifyZeroKnowledgeProof(c.ciphersuite, id, pk, proof)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if ok {
				t.Fatal("expected malformed proof to be rejected")
			}
		}); has {
			t.Fatalf("unexpected panic: %v", err)
		}
	})
}

func TestSignature_Clear(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		k := c.group.NewScalar().Random()
		sk := c.group.NewScalar().Random()
		pk := c.group.Base().Multiply(sk)
		id := uint16(1)
		s, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, k)
		if err != nil {
			t.Fatal(err)
		}
		s.Clear()

		if !s.R.IsIdentity() {
			t.Fatal()
		}

		if !s.Z.IsZero() {
			t.Fatal()
		}
	})
}

func TestSignature_Clear_Hardening(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		t.Run("nil receiver", func(t *testing.T) {
			var s *dkg.Signature
			if has, err := hasPanic(func() { s.Clear() }); has {
				t.Fatalf("unexpected panic: %v", err)
			}
		})

		t.Run("malformed wrapper", func(t *testing.T) {
			s := &dkg.Signature{
				Group: c.group,
				R:     new(ecc.Element),
				Z:     new(ecc.Scalar),
			}
			r := s.R
			z := s.Z
			if has, err := hasPanic(func() { s.Clear() }); has {
				t.Fatalf("unexpected panic: %v", err)
			}
			if s.R != r || s.Z != z {
				t.Fatal("expected malformed signature clear to be a no-op")
			}
		})
	})
}

func TestFrostWrongGroup(t *testing.T) {
	errInvalidCiphersuite := errors.New("invalid ciphersuite")
	testAllCases(t, func(c *testCase) {
		badGroup := dkg.Ciphersuite(2)
		sk := c.group.NewScalar().Random()
		pk := c.group.Base().Multiply(sk)

		// FrostGenerateZeroKnowledgeProof
		if _, err := dkg.FrostGenerateZeroKnowledgeProof(badGroup, 1, sk, pk); err == nil ||
			err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected %q, got %q", errInvalidCiphersuite, err)
		}

		// FrostVerifyZeroKnowledgeProof
		p, err := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, 1, sk, pk)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dkg.FrostVerifyZeroKnowledgeProof(badGroup, 1, pk, p); err == nil ||
			err.Error() != errInvalidCiphersuite.Error() {
			t.Fatalf("expected %q, got %q", errInvalidCiphersuite, err)
		}
	})
}

func hasPanic(f func()) (has bool, err error) {
	defer func() {
		var report any
		if report = recover(); report != nil {
			has = true
			err = fmt.Errorf("%v", report)
		}
	}()

	f()

	return has, err
}

// testPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns an error.
func testPanic(s string, expectedError error, f func()) error {
	errNoPanic := errors.New("no panic")
	errNoPanicMessage := errors.New("panic but no message")

	hasPanic, err := hasPanic(f)

	// if there was no panic
	if !hasPanic {
		return errNoPanic
	}

	// panic, and we don't expect a particular message
	if expectedError == nil {
		return nil
	}

	// panic, but the panic value is empty
	if err == nil {
		return errNoPanicMessage
	}

	// panic, but the panic value is not what we expected
	if err.Error() != expectedError.Error() {
		return fmt.Errorf("expected panic on %s with message %q, got %q", s, expectedError, err)
	}

	return nil
}
