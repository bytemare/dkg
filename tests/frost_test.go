// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests_test

import (
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

		s := dkg.FrostGenerateZeroKnowledgeProof(c.group, id, sk, pk, k)

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
			R: readHexElement(t, c.group, c.zk.r),
			Z: readHexScalar(t, c.group, c.zk.z),
		}

		if !dkg.FrostVerifyZeroKnowledgeProof(c.group, id, pk, s) {
			t.Fatal()
		}
	})
}

func TestSignature_Clear(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		k := c.group.NewScalar().Random()
		sk := c.group.NewScalar().Random()
		pk := c.group.Base().Multiply(sk)
		id := uint64(1)
		s := dkg.FrostGenerateZeroKnowledgeProof(c.group, id, sk, pk, k)
		s.Clear()

		if !s.R.IsIdentity() {
			t.Fatal()
		}

		if !s.Z.IsZero() {
			t.Fatal()
		}
	})
}
