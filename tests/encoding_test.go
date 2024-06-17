// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests_test

import (
	"encoding/json"
	"testing"

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

	if _, _, err = p1.Finalize(p1r1, p1r2); err != nil {
		t.Fatal(err)
	}

	if _, _, err = p2.Finalize(p2r1, p2r2); err != nil {
		t.Fatal(err)
	}

	if _, _, err = p3.Finalize(p3r1, p3r2); err != nil {
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
