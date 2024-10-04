// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/bytemare/dkg"
)

type serde interface {
	Encode() []byte
	Decode([]byte) error
	Hex() string
	DecodeHex(string) error
	json.Unmarshaler
}

func testByteEncoding(in, out serde) error {
	bEnc := in.Encode()

	if err := out.Decode(bEnc); err != nil {
		return err
	}

	return nil
}

func testHexEncoding(in, out serde) error {
	h := in.Hex()

	if err := out.DecodeHex(h); err != nil {
		return err
	}

	return nil
}

func testJSONEncoding(in, out serde) error {
	jsonEnc, err := json.Marshal(in)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(jsonEnc, out); err != nil {
		return err
	}

	return nil
}

func testAndCompareSerdeSimple(in serde, maker func() serde, tester, compare func(a, b serde) error) error {
	out := maker()

	if err := tester(in, out); err != nil {
		return err
	}

	if err := compare(in, out); err != nil {
		return err
	}

	return nil
}

func testAndCompareSerde(in serde, maker func() serde, compare func(a, b serde) error) error {
	if err := testAndCompareSerdeSimple(in, maker, testByteEncoding, compare); err != nil {
		return fmt.Errorf("byte encoding error: %w", err)
	}

	if err := testAndCompareSerdeSimple(in, maker, testHexEncoding, compare); err != nil {
		return fmt.Errorf("hex encoding error: %w", err)
	}

	if err := testAndCompareSerdeSimple(in, maker, testJSONEncoding, compare); err != nil {
		return fmt.Errorf("json encoding error: %w", err)
	}

	return nil
}

func testR1Encoding(t *testing.T, r *dkg.Round1Data) {
	if err := testAndCompareSerde(r, func() serde {
		return new(dkg.Round1Data)
	}, compareR1Data); err != nil {
		t.Fatal(err)
	}
}

func testR2Encoding(t *testing.T, d map[uint16]*dkg.Round2Data) {
	for _, r := range d {
		if err := testAndCompareSerde(r, func() serde {
			return new(dkg.Round2Data)
		}, compareR2Data); err != nil {
			t.Fatal(err)
		}
	}
}

func compareSignatures(a, b serde) error {
	s1, s2 := a.(*dkg.Signature), b.(*dkg.Signature)

	if s1.Group != s2.Group {
		return fmt.Errorf("Expected equality on Group:\n\t%v\n\t%v\n", s1.Group, s2.Group)
	}

	if !s1.R.Equal(s2.R) {
		return fmt.Errorf("Expected equality on R:\n\t%s\n\t%s\n", s1.R.Hex(), s2.R.Hex())
	}

	if !s1.Z.Equal(s2.Z) {
		return fmt.Errorf("Expected equality on Z:\n\t%s\n\t%s\n", s1.Z.Hex(), s2.Z.Hex())
	}

	return nil
}

func compareR1Data(a, b serde) error {
	d1, d2 := a.(*dkg.Round1Data), b.(*dkg.Round1Data)

	if d1.Group != d2.Group {
		return errors.New("expected same group")
	}

	if d1.SenderIdentifier != d2.SenderIdentifier {
		return errors.New("expected same id")
	}

	if !d1.ProofOfKnowledge.R.Equal(d2.ProofOfKnowledge.R) {
		return errors.New("expected same r proof")
	}

	if !d1.ProofOfKnowledge.Z.Equal(d2.ProofOfKnowledge.Z) {
		return errors.New("expected same z proof")
	}

	if len(d1.Commitment) != len(d2.Commitment) {
		return errors.New("different lengths of commitment")
	}

	for i, d := range d1.Commitment {
		if !d.Equal(d2.Commitment[i]) {
			return errors.New("expected same commitment")
		}
	}

	return nil
}

func compareR2Data(a, b serde) error {
	d1, d2 := a.(*dkg.Round2Data), b.(*dkg.Round2Data)

	if d1.Group != d2.Group {
		return errors.New("expected same group")
	}

	if d1.SenderIdentifier != d2.SenderIdentifier {
		return errors.New("expected same sender id")
	}

	if d1.RecipientIdentifier != d2.RecipientIdentifier {
		return errors.New("expected same receiver id")
	}

	if !d1.SecretShare.Equal(d2.SecretShare) {
		return errors.New("expected same secret share")
	}

	return nil
}

func Test_Encoding_R1R2(t *testing.T) {
	c := dkg.Ristretto255Sha512
	maxSigners := uint16(3)
	threshold := uint16(2)

	p1, _ := c.NewParticipant(1, threshold, maxSigners)
	p2, _ := c.NewParticipant(2, threshold, maxSigners)
	p3, _ := c.NewParticipant(3, threshold, maxSigners)

	r1P1 := p1.Start()
	r1P2 := p2.Start()
	r1P3 := p3.Start()

	testR1Encoding(t, r1P1)
	testR1Encoding(t, r1P2)
	testR1Encoding(t, r1P3)

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

	testR2Encoding(t, r2P1)
	testR2Encoding(t, r2P2)
	testR2Encoding(t, r2P3)

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

func TestSignature_Encoding(t *testing.T) {
	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)

		signature := p[0].Start().ProofOfKnowledge

		if err := testAndCompareSerde(signature, func() serde {
			return new(dkg.Signature)
		}, compareSignatures); err != nil {
			t.Fatal(err)
		}
	})
}

func replaceStringInBytes(data []byte, old, new string) []byte {
	s := string(data)
	s = strings.Replace(s, old, new, 1)

	return []byte(s)
}
