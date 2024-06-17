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

	group "github.com/bytemare/crypto"
)

// Round1Data is the output data of the Start() function, to be broadcast to all participants.
type Round1Data struct {
	ProofOfKnowledge *Signature       `json:"proof"`
	Commitment       []*group.Element `json:"com"`
	SenderIdentifier uint64           `json:"senderId"`
	Group            group.Group      `json:"group"`
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
	}

	for i := range p.threshold {
		d.Commitment[i] = p.group.NewElement()
	}

	return d
}

// Encode returns a compact byte serialization of Round1Data.
func (d *Round1Data) Encode() []byte {
	size := 1 + 2 + 8 + d.Group.ElementLength() + d.Group.ScalarLength() + len(d.Commitment)*d.Group.ElementLength()
	out := make([]byte, 11, size)
	out[0] = byte(d.Group)
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(d.Commitment)))
	binary.LittleEndian.PutUint64(out[3:11], d.SenderIdentifier)
	out = append(out, d.ProofOfKnowledge.R.Encode()...)
	out = append(out, d.ProofOfKnowledge.Z.Encode()...)

	for _, c := range d.Commitment {
		out = append(out, c.Encode()...)
	}

	return out
}

func readScalarFromBytes(g group.Group, data []byte, offset int) (*group.Scalar, int, bool) {
	s := g.NewScalar()
	if err := s.Decode(data[offset : offset+g.ScalarLength()]); err != nil {
		return nil, offset, false
	}

	return s, offset + g.ScalarLength(), true
}

func readElementFromBytes(g group.Group, data []byte, offset int) (*group.Element, int, bool) {
	e := g.NewElement()
	if err := e.Decode(data[offset : offset+g.ElementLength()]); err != nil {
		return nil, offset, false
	}

	return e, offset + g.ElementLength(), true
}

// Decode deserializes a valid byte encoding of Round1Data.
func (d *Round1Data) Decode(data []byte) error {
	if len(data) == 0 {
		return errDecodeNoMessage
	}

	if len(data) < 3 {
		return errDecodeNoHeader
	}

	c := Ciphersuite(data[0])
	if !c.Available() || c != Ciphersuite(d.Group) {
		return errInvalidCiphersuite
	}

	g := group.Group(c)
	nbCom := int(binary.LittleEndian.Uint16(data[1:3]))

	expectedSize := 1 + 2 + 8 + g.ElementLength() + g.ScalarLength() + nbCom*g.ElementLength()
	if len(data) != expectedSize {
		return errDecodeInvalidLength
	}

	id := binary.LittleEndian.Uint64(data[3:11])
	offset := 11

	r, offset, success := readElementFromBytes(g, data, offset)
	if !success {
		return errDecodeProofR
	}

	z, offset, success := readScalarFromBytes(g, data, offset)
	if !success {
		return errDecodeProofZ
	}

	com := make([]*group.Element, nbCom)
	for i := range nbCom {
		com[i], offset, success = readElementFromBytes(g, data, offset)
		if !success {
			return errDecodeCommitment
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

	size := 1 + 16 + g.ScalarLength()
	if len(data) != size {
		return errDecodeInvalidLength
	}

	s := binary.LittleEndian.Uint64(data[1:9])
	r := binary.LittleEndian.Uint64(data[9:17])

	share, _, success := readScalarFromBytes(g, data, 17)
	if !success {
		return errDecodeSecretShare
	}

	d.Group = g
	d.SecretShare = share
	d.SenderIdentifier = s
	d.RecipientIdentifier = r

	return nil
}
