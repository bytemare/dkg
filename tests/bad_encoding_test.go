// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ecc/debug"

	"github.com/bytemare/dkg"
)

func TestRound1_Decode_Fail(t *testing.T) {
	errDecodeInvalidLength := "failed to decode Round 1 data: invalid encoding length"
	errInvalidCiphersuite := "failed to decode Round 1 data: invalid ciphersuite"
	errDecodeProofR := "failed to decode Round 1 data: invalid encoding of R proof"
	errDecodeProofZ := "failed to decode Round 1 data: invalid encoding of z proof"
	errDecodeCommitment := "failed to decode Round 1 data: invalid encoding of commitment"
	errDecodeHex := "failed to decode Round 1 data: encoding/hex: odd length hex string"

	testAllCases(t, func(c *testCase) {
		p, _ := c.ciphersuite.NewParticipant(1, c.threshold, c.maxParticipants)
		r1 := p.Start()
		decoded := new(dkg.Round1Data)

		// nil or len = 0
		if err := testDecodingBytesNilEmpty(decoded, errDecodeInvalidLength); err != nil {
			t.Fatal(err)
		}

		// invalid ciphersuite
		if err := testDecodeBytesBadCiphersuite(decoded, 6, errInvalidCiphersuite); err != nil {
			t.Fatal(err)
		}

		// invalid length: to low, too high
		expectedSize := 1 + 2 + 2 + c.group.ElementLength() + c.group.ScalarLength() + int(
			c.threshold,
		)*c.group.ElementLength()
		data := make([]byte, expectedSize+1)
		data[0] = byte(c.ciphersuite)
		data[3] = byte(c.threshold)

		expected := fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, len(data))
		if err := decoded.Decode(data); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		expected = fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, expectedSize-1)
		if err := decoded.Decode(data[:expectedSize-1]); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// proof: bad r
		data = r1.Encode()
		bad := slices.Replace(data, 5, 5+c.group.ElementLength(), debug.BadElementOffCurve(c.group)...)

		if err := decoded.Decode(bad); err == nil || !strings.HasPrefix(err.Error(), errDecodeProofR) {
			t.Fatalf("expected error %q, got %q", errDecodeProofR, err)
		}

		// proof: bad z
		data = r1.Encode()
		bad = slices.Replace(
			data,
			5+c.group.ElementLength(),
			5+c.group.ElementLength()+c.group.ScalarLength(),
			debug.BadScalarHigh(c.group)...)

		if err := decoded.Decode(bad); err == nil || !strings.HasPrefix(err.Error(), errDecodeProofZ) {
			t.Fatalf("expected error %q, got %q", errDecodeProofZ, err)
		}

		// commitment: some error in one of the elements
		data = make([]byte, 5, expectedSize)
		data[0] = byte(c.group)
		binary.LittleEndian.PutUint16(data[1:3], 1)
		binary.LittleEndian.PutUint16(data[3:5], c.threshold)
		data = append(data, c.group.Base().Encode()...)
		data = append(data, c.group.NewScalar().Random().Encode()...)
		for range c.threshold {
			data = append(data, debug.BadElementOffCurve(c.group)...)
		}

		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), errDecodeCommitment) {
			t.Fatalf("expected error %q, got %q", errDecodeCommitment, err)
		}

		// Hex: bad hex
		if err := testDecodeHexOddLength(r1, decoded, errDecodeHex); err != nil {
			t.Fatal(err)
		}

		// JSON
		errDecodeJSON := "failed to decode Round 1 data: failed to decode Signature: invalid JSON encoding"

		if err := jsonTester("failed to decode Round 1 data", errDecodeJSON, r1, decoded,
			jsonTesterBaddie{
				fmt.Sprintf("\"r\":\"%s\"", r1.ProofOfKnowledge.R.Hex()),
				fmt.Sprintf("\"r\":\"%s\"", hex.EncodeToString(debug.BadElementOffCurve(c.group))),
				"failed to decode Round 1 data: failed to decode Signature: element DecodeHex: ",
			},
			jsonTesterBaddie{
				"commitment\"",
				"commitment\":[], \"oldCommitment\"",
				"failed to decode Round 1 data: missing commitment",
			},
		); err != nil {
			t.Fatal(err)
		}

		// UnmarshallJSON: excessive commitment length
		r1.Commitment = make([]*ecc.Element, 65536)
		for i := range 65536 {
			r1.Commitment[i] = c.group.NewElement()
		}

		data, err := json.Marshal(r1)
		if err != nil {
			t.Fatal(err)
		}

		errInvalidPolynomialLength := "failed to decode Round 1 data: invalid polynomial length (exceeds uint16 limit 65535)"

		if err = json.Unmarshal(data, decoded); err == nil ||
			!strings.HasPrefix(err.Error(), errInvalidPolynomialLength) {
			t.Fatalf("expected error %q, got %q", errInvalidPolynomialLength, err)
		}
	})
}

func TestRound2_Decode_Fail(t *testing.T) {
	errDecodeInvalidLength := "failed to decode Round 2 data: invalid encoding length"
	errInvalidCiphersuite := "failed to decode Round 2 data: invalid ciphersuite"
	errDecodeSecretShare := "failed to decode Round 2 data: invalid encoding of secret share"
	errDecodeHex := "failed to decode Round 2 data: encoding/hex: odd length hex string"

	testAllCases(t, func(c *testCase) {
		decoded := new(dkg.Round2Data)

		// nil or len = 0
		if err := testDecodingBytesNilEmpty(decoded, errDecodeInvalidLength); err != nil {
			t.Fatal(err)
		}

		// invalid ciphersuite
		if err := testDecodeBytesBadCiphersuite(decoded, 6, errInvalidCiphersuite); err != nil {
			t.Fatal(err)
		}

		// invalid length: too short, too long
		expectedSize := 1 + 4 + c.group.ScalarLength()
		data := make([]byte, expectedSize+1)
		data[0] = byte(c.ciphersuite)

		expected := fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, len(data))
		if err := decoded.Decode(data); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		expected = fmt.Sprintf("%s: expected %d got %d", errDecodeInvalidLength, expectedSize, expectedSize-1)
		if err := decoded.Decode(data[:expectedSize-1]); err == nil || err.Error() != expected {
			t.Fatalf("expected error %q, got %q", expected, err)
		}

		// bad share encoding
		data = make([]byte, 5, expectedSize)
		data[0] = byte(c.group)
		binary.LittleEndian.PutUint16(data[1:3], 1)
		binary.LittleEndian.PutUint16(data[3:5], 2)
		data = append(data, debug.BadScalarHigh(c.group)...)

		if err := decoded.Decode(data); err == nil || !strings.HasPrefix(err.Error(), errDecodeSecretShare) {
			t.Fatalf("expected error %q, got %q", errDecodeSecretShare, err)
		}

		// Hex: bad hex
		r2 := &dkg.Round2Data{
			SecretShare:         c.group.NewScalar().Random(),
			SenderIdentifier:    c.threshold,
			RecipientIdentifier: c.maxParticipants,
			Group:               c.group,
		}

		// Hex: bad hex
		if err := testDecodeHexOddLength(r2, decoded, errDecodeHex); err != nil {
			t.Fatal(err)
		}

		// JSON
		errDecodeJSON := "failed to decode Round 2 data: invalid JSON encoding"

		if err := jsonTester("failed to decode Round 2 data", errDecodeJSON, r2, decoded,
			jsonTesterBaddie{
				fmt.Sprintf("\"secretShare\":\"%s\"", r2.SecretShare.Hex()),
				fmt.Sprintf("\"secretShare\":\"%s\"", hex.EncodeToString(debug.BadScalarHigh(c.group))),
				"failed to decode Round 2 data: scalar DecodeHex: ",
			}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSignature_Decode_Fail(t *testing.T) {
	errDecodeInvalidLength := "failed to decode Signature: invalid encoding length"
	errInvalidCiphersuite := "failed to decode Signature: invalid ciphersuite"
	errDecodeR := "failed to decode Signature: invalid encoding of R proof: element Decode: "
	errDecodeZ := "failed to decode Signature: invalid encoding of z proof: scalar Decode: "
	errDecodeHex := "failed to decode Signature: encoding/hex: odd length hex string"

	testAllCases(t, func(c *testCase) {
		p := c.makeParticipants(t)
		signature := p[0].Start().ProofOfKnowledge
		decoded := new(dkg.Signature)

		// nil or len = 0
		if err := testDecodingBytesNilEmpty(decoded, errDecodeInvalidLength); err != nil {
			t.Fatal(err)
		}

		// invalid ciphersuite
		if err := testDecodeBytesBadCiphersuite(decoded, 2, errInvalidCiphersuite); err != nil {
			t.Fatal(err)
		}

		// Bytes: invalid length
		encoded := signature.Encode()
		if err := decoded.Decode(encoded[:1]); err == nil || err.Error() != errDecodeInvalidLength {
			t.Fatalf("expected error %q, got %q", errDecodeInvalidLength, err)
		}

		badLength := (1 + c.group.ElementLength() + c.group.ScalarLength()) - 1

		if err := decoded.Decode(encoded[:badLength]); err == nil || err.Error() != errDecodeInvalidLength {
			t.Fatalf("expected error %q, got %q", errDecodeInvalidLength, err)
		}

		tooLong := append(encoded, []byte{1}...)
		if err := decoded.Decode(tooLong); err == nil || err.Error() != errDecodeInvalidLength {
			t.Fatalf("expected error %q, got %q", errDecodeInvalidLength, err)
		}

		// Bytes: Bad R
		bad := slices.Replace(encoded, 1, 1+c.group.ElementLength(), debug.BadElementOffCurve(c.group)...)
		if err := decoded.Decode(bad); err == nil || !strings.HasPrefix(err.Error(), errDecodeR) {
			t.Fatalf("expected error %q, got %q", errDecodeR, err)
		}

		// Bytes: Bad Z
		encoded = signature.Encode()
		bad = slices.Replace(
			encoded,
			1+c.group.ElementLength(),
			1+c.group.ElementLength()+c.group.ScalarLength(),
			debug.BadScalarHigh(c.group)...)
		if err := decoded.Decode(bad); err == nil || !strings.HasPrefix(err.Error(), errDecodeZ) {
			t.Fatalf("expected error %q, got %q", errDecodeZ, err)
		}

		// Hex: bad hex
		if err := testDecodeHexOddLength(signature, decoded, errDecodeHex); err != nil {
			t.Fatal(err)
		}

		// JSON
		errDecodeJSON := "failed to decode Signature: invalid JSON encoding"

		if err := jsonTester("failed to decode Signature", errDecodeJSON, signature, decoded,
			jsonTesterBaddie{
				fmt.Sprintf("\"r\":\"%s\"", signature.R.Hex()),
				fmt.Sprintf("\"r\":\"%s\"", hex.EncodeToString(bad)),
				"failed to decode Signature: element DecodeHex: ",
			}); err != nil {
			t.Fatal(err)
		}
	})
}

func testDecodingBytesNilEmpty(decoder serde, expectedError string) error {
	// nil input
	if err := decoder.Decode(nil); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	// empty input
	if err := decoder.Decode([]byte{}); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	return nil
}

func testDecodeBytesBadCiphersuite(decoder serde, headerLength int, expectedError string) error {
	input := make([]byte, headerLength)
	input[0] = 2

	if err := decoder.Decode(input); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	return nil
}

func testDecodeHexOddLength(encoder, decoder serde, expectedError string) error {
	h := encoder.Hex()
	if err := decoder.DecodeHex(h[:len(h)-1]); err == nil || err.Error() != expectedError {
		return fmt.Errorf("expected error %q, got %q", expectedError, err)
	}

	return nil
}

type jsonTesterBaddie struct {
	key, value, expectedError string
}

func testJSONBaddie(in any, decoded json.Unmarshaler, baddie jsonTesterBaddie) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}

	data = replaceStringInBytes(data, baddie.key, baddie.value)

	if err = json.Unmarshal(data, decoded); err == nil ||
		!strings.HasPrefix(err.Error(), baddie.expectedError) {
		return fmt.Errorf("expected error %q, got %q", baddie.expectedError, err)
	}

	return nil
}

func jsonTester(errPrefix, badJSONErr string, in any, decoded json.Unmarshaler, baddies ...jsonTesterBaddie) error {
	errInvalidCiphersuite := errPrefix + ": invalid ciphersuite"

	// JSON: bad json
	baddie := jsonTesterBaddie{
		key:           "\"group\"",
		value:         "bad",
		expectedError: "invalid character 'b' looking for beginning of object key string",
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad group
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":2, \"oldGroup\"",
		expectedError: errInvalidCiphersuite,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":70, \"oldGroup\"",
		expectedError: errInvalidCiphersuite,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":-1, \"oldGroup\"",
		expectedError: badJSONErr,
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// UnmarshallJSON: bad ciphersuite
	overflow := "9223372036854775808" // MaxInt64 + 1
	baddie = jsonTesterBaddie{
		key:           "\"group\"",
		value:         "\"group\":" + overflow + ", \"oldGroup\"",
		expectedError: errPrefix + ": failed to read Group: strconv.Atoi: parsing \"9223372036854775808\": value out of range",
	}

	if err := testJSONBaddie(in, decoded, baddie); err != nil {
		return err
	}

	// Replace keys and values
	for _, baddie = range baddies {
		if err := testJSONBaddie(in, decoded, baddie); err != nil {
			return err
		}
	}

	return nil
}
