// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/bytemare/ecc"
)

var (
	errRound1DecodePrefix = errors.New("failed to decode Round 1 data")
	errRound2DecodePrefix = errors.New("failed to decode Round 2 data")
)

// Round1Data is the output data of the Start() function, to be broadcast to all participants.
type Round1Data struct {
	ProofOfKnowledge *Signature     `json:"proof"`
	Commitment       []*ecc.Element `json:"commitment"`
	SenderIdentifier uint16         `json:"senderId"`
	Group            ecc.Group      `json:"group"`
}

// Encode returns a compact byte serialization of Round1Data.
func (d *Round1Data) Encode() []byte {
	size := 1 + 2 + 2 + d.Group.ElementLength() + d.Group.ScalarLength() + len(d.Commitment)*d.Group.ElementLength()
	out := make([]byte, 5, size)
	out[0] = byte(d.Group)
	binary.LittleEndian.PutUint16(out[1:3], d.SenderIdentifier)
	binary.LittleEndian.PutUint16(out[3:5], uint16(len(d.Commitment)))
	out = append(out, d.ProofOfKnowledge.R.Encode()...)
	out = append(out, d.ProofOfKnowledge.Z.Encode()...)

	for _, c := range d.Commitment {
		out = append(out, c.Encode()...)
	}

	return out
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (d *Round1Data) Hex() string {
	return hex.EncodeToString(d.Encode())
}

func readScalarFromBytes(g ecc.Group, data []byte, offset int) (*ecc.Scalar, int, error) {
	s := g.NewScalar()
	if err := s.Decode(data[offset : offset+g.ScalarLength()]); err != nil {
		return nil, offset, fmt.Errorf("%w", err)
	}

	return s, offset + g.ScalarLength(), nil
}

func readElementFromBytes(g ecc.Group, data []byte, offset int) (*ecc.Element, int, error) {
	e := g.NewElement()
	if err := e.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return nil, offset, fmt.Errorf("%w", err)
	}

	return e, offset + g.ElementLength(), nil
}

// Decode deserializes a valid byte encoding of Round1Data.
func (d *Round1Data) Decode(data []byte) error {
	if len(data) <= 5 {
		return fmt.Errorf("%w: %w", errRound1DecodePrefix, errEncodingInvalidLength)
	}

	c := Ciphersuite(data[0])
	if !c.Available() {
		return fmt.Errorf("%w: %w", errRound1DecodePrefix, errInvalidCiphersuite)
	}

	id := binary.LittleEndian.Uint16(data[1:3])
	comLen := int(binary.LittleEndian.Uint16(data[3:5]))
	g := ecc.Group(c)

	expectedSize := 1 + 2 + 2 + g.ElementLength() + g.ScalarLength() + comLen*g.ElementLength()
	if len(data) != expectedSize {
		return fmt.Errorf(
			"%w: %w: expected %d got %d",
			errRound1DecodePrefix,
			errDecodeInvalidLength,
			expectedSize,
			len(data),
		)
	}

	offset := 5

	r, offset, err := readElementFromBytes(g, data, offset)
	if err != nil {
		return fmt.Errorf("%w: %w: %w", errRound1DecodePrefix, errDecodeProofR, err)
	}

	z, offset, err := readScalarFromBytes(g, data, offset)
	if err != nil {
		return fmt.Errorf("%w: %w: %w", errRound1DecodePrefix, errDecodeProofZ, err)
	}

	com := make([]*ecc.Element, comLen)
	for i := range comLen {
		com[i], offset, err = readElementFromBytes(g, data, offset)
		if err != nil {
			return fmt.Errorf("%w: %w: %w", errRound1DecodePrefix, errDecodeCommitment, err)
		}
	}

	d.Group = g
	d.SenderIdentifier = id
	d.ProofOfKnowledge = &Signature{
		Group: g,
		R:     r,
		Z:     z,
	}
	d.Commitment = com

	return nil
}

// DecodeHex sets k to the decoding of the hex encoded representation returned by Hex().
func (d *Round1Data) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w: %w", errRound1DecodePrefix, err)
	}

	return d.Decode(b)
}

// UnmarshalJSON reads the input data as JSON and deserializes it into the receiver. It doesn't modify the receiver when
// encountering an error.
func (d *Round1Data) UnmarshalJSON(data []byte) error {
	r := new(r1DataShadow)
	if err := unmarshalJSON(data, r); err != nil {
		return fmt.Errorf("%w: %w", errRound1DecodePrefix, err)
	}

	if len(r.Commitment) == 0 {
		return fmt.Errorf("%w: missing commitment", errRound1DecodePrefix)
	}

	*d = Round1Data(*r)

	return nil
}

// Round2Data is an output of the Continue() function, to be sent to the Receiver.
type Round2Data struct {
	SecretShare         *ecc.Scalar `json:"secretShare"`
	SenderIdentifier    uint16      `json:"senderId"`
	RecipientIdentifier uint16      `json:"recipientId"`
	Group               ecc.Group   `json:"group"`
}

// Encode returns a compact byte serialization of Round2Data.
func (d *Round2Data) Encode() []byte {
	size := 1 + 4 + d.Group.ScalarLength()
	out := make([]byte, 5, size)
	out[0] = byte(d.Group)
	binary.LittleEndian.PutUint16(out[1:3], d.SenderIdentifier)
	binary.LittleEndian.PutUint16(out[3:5], d.RecipientIdentifier)
	out = append(out, d.SecretShare.Encode()...)

	return out
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (d *Round2Data) Hex() string {
	return hex.EncodeToString(d.Encode())
}

// Decode deserializes a valid byte encoding of Round2Data.
func (d *Round2Data) Decode(data []byte) error {
	if len(data) <= 5 {
		return fmt.Errorf("%w: %w", errRound2DecodePrefix, errEncodingInvalidLength)
	}

	c := Ciphersuite(data[0])
	if !c.Available() {
		return fmt.Errorf("%w: %w", errRound2DecodePrefix, errInvalidCiphersuite)
	}

	g := ecc.Group(c)

	expectedSize := 1 + 2 + 2 + g.ScalarLength()
	if len(data) != expectedSize {
		return fmt.Errorf(
			"%w: %w: expected %d got %d",
			errRound2DecodePrefix,
			errDecodeInvalidLength,
			expectedSize,
			len(data),
		)
	}

	s := binary.LittleEndian.Uint16(data[1:3])
	r := binary.LittleEndian.Uint16(data[3:5])

	share, _, err := readScalarFromBytes(g, data, 5)
	if err != nil {
		return fmt.Errorf("%w: %w: %w", errRound2DecodePrefix, errDecodeSecretShare, err)
	}

	d.Group = g
	d.SecretShare = share
	d.SenderIdentifier = s
	d.RecipientIdentifier = r

	return nil
}

// DecodeHex sets k to the decoding of the hex encoded representation returned by Hex().
func (d *Round2Data) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w: %w", errRound2DecodePrefix, err)
	}

	return d.Decode(b)
}

// UnmarshalJSON reads the input data as JSON and deserializes it into the receiver. It doesn't modify the receiver when
// encountering an error.
func (d *Round2Data) UnmarshalJSON(data []byte) error {
	r := new(r2DataShadow)
	if err := unmarshalJSON(data, r); err != nil {
		return fmt.Errorf("%w: %w", errRound2DecodePrefix, err)
	}

	*d = Round2Data(*r)

	return nil
}

func jsonReGetField(key, s, catch string) (string, error) {
	r := fmt.Sprintf(`%q:%s`, key, catch)
	re := regexp.MustCompile(r)
	matches := re.FindStringSubmatch(s)

	if len(matches) != 2 {
		return "", errEncodingInvalidJSONEncoding
	}

	return matches[1], nil
}

// jsonReGetGroup attempts to find the Ciphersuite JSON encoding in s.
func jsonReGetGroup(s string) (Ciphersuite, error) {
	f, err := jsonReGetField("group", s, `(\w+)`)
	if err != nil {
		return 0, err
	}

	i, err := strconv.Atoi(f)
	if err != nil {
		return 0, fmt.Errorf("failed to read Group: %w", err)
	}

	if i < 0 || i > 63 {
		return 0, errInvalidCiphersuite
	}

	c := Ciphersuite(i)
	if !c.Available() {
		return 0, errInvalidCiphersuite
	}

	return c, nil
}
