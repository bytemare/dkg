// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests

/*
type vectorConf struct {
	Threshold        uint            `json:"threshold"`
	MaxParticipants  uint            `json:"maxParticipants"`
	SenderId         uint64          `json:"senderId"`
	RecipientID      uint64          `json:"recipientID"`
	SenderPolynomial []*group.Scalar `json:"senderPolynomial"`
	Random           *group.Scalar   `json:"random"`
}

type vectorR1 struct {
	Sk           *group.Scalar     `json:"sk"`
	Pk           *group.Element    `json:"pk"`
	R            *group.Element    `json:"r"`
	Z            *group.Scalar     `json:"z"`
	SenderR1Data []*dkg.Round1Data `json:"senderR1Data"`
}

func (v vectorR1) isEquivalent(v2 *vectorR1) bool {
	if v.Sk.Equal(v2.Sk) != 1 ||
		v.Pk.Equal(v2.Pk) != 1 ||
		v.R.Equal(v2.R) != 1 ||
		v.Z.Equal(v2.Z) != 1 ||
		len(v.SenderR1Data) != len(v2.SenderR1Data) {
		return false
	}

	for i, s2 := range v2.SenderR1Data {
		r := v.SenderR1Data[i]
		if s2.SenderIdentifier != r.SenderIdentifier ||
			s2.Group != r.Group ||
			s2.ProofOfKnowledge.R.Equal(r.ProofOfKnowledge.R) != 1 ||
			s2.ProofOfKnowledge.Z.Equal(r.ProofOfKnowledge.Z) != 1 ||
			len(s2.Commitment) != len(r.Commitment) {
			return false
		}

		for j, c := range s2.Commitment {
			if c.Equal(r.Commitment[j]) != 1 {
				return false
			}
		}
	}

	return true
}

type vectorR2 struct {
	GroupPubKey  *group.Element  `json:"GroupPubKey"`
	SenderR2Data *dkg.Round2Data `json:"senderR2Data"`
}

func (v vectorR2) isEquivalent(v2 *vectorR2) bool {
	return v.GroupPubKey.Equal(v2.GroupPubKey) == 1 &&
		v.SenderR2Data.SecretShare.Equal(v2.SenderR2Data.SecretShare) == 1 &&
		v.SenderR2Data.SenderIdentifier == v2.SenderR2Data.SenderIdentifier &&
		v.SenderR2Data.RecipientIdentifier == v2.SenderR2Data.RecipientIdentifier &&
		v.SenderR2Data.Group == v2.SenderR2Data.Group
}

type vector struct {
	vectorConf
	vectorR1
	vectorR2
}

type testEncoding struct {
	Name        string          `json:"name"`
	Ciphersuite dkg.Ciphersuite `json:"ciphersuite"`
	Group       group.Group     `json:"group"`
	Vectors     []*vector       `json:"vectors"`
}

func newVector(g group.Group, threshold, max uint, sender, receiver uint64, random *group.Scalar, poly ...*group.Scalar) *vector {
	v := &vector{
		vectorConf: vectorConf{
			Threshold:       threshold,
			MaxParticipants: max,
			SenderId:        sender,
			RecipientID:     receiver,
		},
	}

	if len(poly) == 0 {
		poly = secretsharing.NewPolynomial(v.Threshold)
		for i := range v.Threshold {
			poly[i] = g.NewScalar().Random()
		}
	}

	v.SenderPolynomial = poly
	v.Random = random

	return v
}

func (v *vector) makeParticipants(t *testing.T, c dkg.Ciphersuite) []*dkg.Participant {
	ps := make([]*dkg.Participant, 0, v.MaxParticipants)
	for i := range uint64(v.MaxParticipants) {
		p, err := c.NewParticipant(i+1, v.MaxParticipants, v.Threshold)
		if err != nil {
			t.Fatal(err)
		}

		ps = append(ps, p)
	}

	return ps
}

func (v *vector) run(t *testing.T, c dkg.Ciphersuite, g group.Group) {
	p := v.makeParticipants(t, c)
	p1, err := c.NewParticipant(v.SenderId, v.MaxParticipants, v.Threshold, v.SenderPolynomial...)
	if err != nil {
		t.Fatal(err)
	}

	p2, err := c.NewParticipant(v.RecipientID, v.MaxParticipants, v.Threshold)
	if err != nil {
		t.Fatal(err)
	}

	p[0] = p1
	p[1] = p2

	r1 := make([]*dkg.Round1Data, v.MaxParticipants)
	r1[0] = p[0].StartWithRandom(v.Random)
	for i, pi := range p[1:] {
		r1[i+1] = pi.Start()
	}

	r2 := make(map[uint64][]*dkg.Round2Data, v.MaxParticipants)
	for i := range v.MaxParticipants {
		r, err := p[i].Continue(r1)
		if err != nil {
			t.Fatal(err)
		}

		// triage r2 data for Finalize()
		for id, data := range r {
			if r2[id] == nil {
				r2[id] = make([]*dkg.Round2Data, 0, v.MaxParticipants-1)
			}
			r2[id] = append(r2[id], data)
		}
	}

	keyShare, gpk, err := p[0].Finalize(r1, r2[p[0].Identifier])
	if err != nil {
		t.Fatal()
	}

	v.GroupPubKey = gpk
	v.Sk = keyShare.SecretKey
	v.Pk = keyShare.PublicKey
	v.R = r1[0].ProofOfKnowledge.R
	v.Z = r1[0].ProofOfKnowledge.Z
	v.SenderR1Data = r1

	for _, r := range r2[v.RecipientID] {
		if r.SenderIdentifier == v.SenderId && r.RecipientIdentifier == v.RecipientID {
			v.SenderR2Data = r
		}
	}

	if v.SenderR2Data == nil {
		t.Fatalf("r2 for %d from %d not found", v.RecipientID, v.SenderId)
	}
}

func TestProduceVectors(t *testing.T) {
	fileName := "encoding-vectors.json"
	configs := [][2]uint{
		{1, 2},
		{3, 5},
		{4, 9},
	}
	nbVectors := 2
	allVectors := make([]*testEncoding, 0, 21)
	testAllCases(t, func(c *testCase) {
		for _, config := range configs {
			te := &testEncoding{
				Name:        fmt.Sprintf("%v - (%d,%d)", c.group, config[0], config[1]),
				Ciphersuite: c.ciphersuite,
				Group:       c.group,
				Vectors:     make([]*vector, nbVectors),
			}

			for nv := range nbVectors {
				v := newVector(c.group, config[0], config[1], rand.Uint64(), rand.Uint64(), c.group.NewScalar().Random())
				v.run(t, te.Ciphersuite, te.Group)
				te.Vectors[nv] = v
			}

			allVectors = append(allVectors, te)
		}
	})

	file, err := json.MarshalIndent(allVectors, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(fileName, file, 0644); err != nil {
		t.Fatal(err)
	}

	vectors := getEncodingVectors(t, fileName)
	for _, te := range vectors {
		t.Run(te.Name, func(t *testing.T) {
			for _, v := range te.Vectors {
				v2 := newVector(te.Group, v.Threshold, v.MaxParticipants, v.SenderId, v.RecipientID, v.Random, v.SenderPolynomial...)
				v2.run(t, te.Ciphersuite, te.Group)
			}
		})
	}
}

func getEncodingVectors(t *testing.T, file string, size, nbVectors int) []testEncoding {
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	vectors := make([]*testEncoding, size)
	for _, te := range vectors {
		te.Vectors = make([]*vector, nbVectors)
		for _, v := range te.Vectors {
			v = &vector{
				vectorConf: vectorConf{
					Threshold:        0,
					MaxParticipants:  0,
					SenderId:         0,
					RecipientID:      0,
					SenderPolynomial: nil,
					Random:           nil,
				},
				vectorR1:   vectorR1{},
				vectorR2:   vectorR2{},
			}
		}
	}


	err = json.Unmarshal(content, &vectors)
	if err != nil {
		t.Fatal(err)
	}

	return vectors
}
*/
