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
	"fmt"

	group "github.com/bytemare/crypto"
)

// Round1Data is the output data of the Start() function, to be broadcast to all participants.
type Round1Data struct {
	ProofOfKnowledge *Signature       `json:"proof"`
	Commitment       []*group.Element `json:"com"`
	SenderIdentifier uint64           `json:"senderId"`
	Group            group.Group      `json:"group"`
	threshold        uint
}

// NewRound1Data initializes a new round 1 data package. Use this to subsequently decode or unmarshal encoded data.
func (p *Participant) NewRound1Data() *Round1Data {
	d := &Round1Data{
		Group: p.group,
		ProofOfKnowledge: &Signature{
			R: p.group.NewElement(),
			Z: p.group.NewScalar(),
		},
		Commitment:       make([]*group.Element, p.threshold),
		SenderIdentifier: 0,
		threshold:        p.threshold,
	}

	for i := range p.threshold {
		d.Commitment[i] = p.group.NewElement()
	}

	return d
}

// Encode returns a compact byte serialization of Round1Data.
func (d *Round1Data) Encode() []byte {
	size := 1 + 8 + d.Group.ElementLength() + d.Group.ScalarLength() + len(d.Commitment)*d.Group.ElementLength()
	out := make([]byte, 9, size)
	out[0] = byte(d.Group)
	binary.LittleEndian.PutUint64(out[1:9], d.SenderIdentifier)
	out = append(out, d.ProofOfKnowledge.R.Encode()...)
	out = append(out, d.ProofOfKnowledge.Z.Encode()...)

	for _, c := range d.Commitment {
		out = append(out, c.Encode()...)
	}

	return out
}

func readScalarFromBytes(g group.Group, data []byte, offset int) (*group.Scalar, int, error) {
	s := g.NewScalar()
	if err := s.Decode(data[offset : offset+g.ScalarLength()]); err != nil {
		return nil, offset, fmt.Errorf("%w", err)
	}

	return s, offset + g.ScalarLength(), nil
}

func readElementFromBytes(g group.Group, data []byte, offset int) (*group.Element, int, error) {
	e := g.NewElement()
	if err := e.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return nil, offset, fmt.Errorf("%w", err)
	}

	return e, offset + g.ElementLength(), nil
}

// Decode deserializes a valid byte encoding of Round1Data.
func (d *Round1Data) Decode(data []byte) error {
	if len(data) == 0 {
		return errDecodeNoMessage
	}

	c := Ciphersuite(data[0])
	if !c.Available() || c != Ciphersuite(d.Group) {
		return errInvalidCiphersuite
	}

	g := group.Group(c)

	expectedSize := 1 + 8 + g.ElementLength() + g.ScalarLength() + int(d.threshold)*g.ElementLength()
	if len(data) != expectedSize {
		return fmt.Errorf("%w: expected %d got %d", errDecodeInvalidLength, expectedSize, len(data))
	}

	id := binary.LittleEndian.Uint64(data[1:9])
	offset := 9

	r, offset, err := readElementFromBytes(g, data, offset)
	if err != nil {
		return fmt.Errorf("%w: %w", errDecodeProofR, err)
	}

	z, offset, err := readScalarFromBytes(g, data, offset)
	if err != nil {
		return fmt.Errorf("%w: %w", errDecodeProofZ, err)
	}

	com := make([]*group.Element, d.threshold)
	for i := range d.threshold {
		com[i], offset, err = readElementFromBytes(g, data, offset)
		if err != nil {
			return fmt.Errorf("%w: %w", errDecodeCommitment, err)
		}
	}

	d.Group = g
	d.SenderIdentifier = id
	d.ProofOfKnowledge = &Signature{
		R: r,
		Z: z,
	}
	d.Commitment = com

	return nil
}

// Round2Data is an output of the Continue() function, to be sent to the Receiver.
type Round2Data struct {
	SecretShare         *group.Scalar `json:"secretShare"`
	SenderIdentifier    uint64        `json:"senderId"`
	RecipientIdentifier uint64        `json:"recipientId"`
	Group               group.Group   `json:"group"`
}

// NewRound2Data initializes a new round 2 data package. Use this to subsequently decode or unmarshal encoded data.
func (p *Participant) NewRound2Data() *Round2Data {
	return &Round2Data{
		Group:               p.group,
		SecretShare:         p.group.NewScalar(),
		SenderIdentifier:    0,
		RecipientIdentifier: 0,
	}
}

// Encode returns a compact byte serialization of Round2Data.
func (d *Round2Data) Encode() []byte {
	size := 1 + 16 + d.Group.ScalarLength()
	out := make([]byte, 17, size)
	out[0] = byte(d.Group)
	binary.LittleEndian.PutUint64(out[1:9], d.SenderIdentifier)
	binary.LittleEndian.PutUint64(out[9:17], d.RecipientIdentifier)
	out = append(out, d.SecretShare.Encode()...)

	return out
}

// Decode deserializes a valid byte encoding of Round2Data.
func (d *Round2Data) Decode(data []byte) error {
	if len(data) == 0 {
		return errDecodeNoMessage
	}

	c := Ciphersuite(data[0])
	if !c.Available() || c != Ciphersuite(d.Group) {
		return errInvalidCiphersuite
	}

	g := group.Group(c)

	expectedSize := 1 + 16 + g.ScalarLength()
	if len(data) != expectedSize {
		return fmt.Errorf("%w: expected %d got %d", errDecodeInvalidLength, expectedSize, len(data))
	}

	s := binary.LittleEndian.Uint64(data[1:9])
	r := binary.LittleEndian.Uint64(data[9:17])

	share, _, err := readScalarFromBytes(g, data, 17)
	if err != nil {
		return fmt.Errorf("%w: %w", errDecodeSecretShare, err)
	}

	d.Group = g
	d.SecretShare = share
	d.SenderIdentifier = s
	d.RecipientIdentifier = r

	return nil
}
