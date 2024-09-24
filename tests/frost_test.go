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
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/dkg"
)

func readHexScalar(t *testing.T, g group.Group, input string) *group.Scalar {
	s := g.NewScalar()
	if err := s.DecodeHex(input); err != nil {
		t.Fatal(err)
	}

	return s
}

func readHexElement(t *testing.T, g group.Group, input string) *group.Element {
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

		if r.Equal(s.R) != 1 {
			t.Fatal()
		}

		if z.Equal(s.Z) != 1 {
			t.Fatal()
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

func TestSignature_Clear(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		k := c.group.NewScalar().Random()
		sk := c.group.NewScalar().Random()
		pk := c.group.Base().Multiply(sk)
		id := uint16(1)
		s, _ := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, id, sk, pk, k)
		s.Clear()

		if !s.R.IsIdentity() {
			t.Fatal()
		}

		if !s.Z.IsZero() {
			t.Fatal()
		}
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
		p, _ := dkg.FrostGenerateZeroKnowledgeProof(c.ciphersuite, 1, sk, pk)
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
