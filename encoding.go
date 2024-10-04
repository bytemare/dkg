// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/bytemare/ecc"
)

var errInvalidPolynomialLength = errors.New("invalid polynomial length (exceeds uint16 limit 65535)")

type shadowInit interface {
	init(g ecc.Group, threshold uint16)
}

type r1DataShadow Round1Data

func (r *r1DataShadow) init(g ecc.Group, threshold uint16) {
	r.Group = g
	r.ProofOfKnowledge = &Signature{
		Group: g,
		R:     g.NewElement(),
		Z:     g.NewScalar(),
	}
	r.Commitment = make([]*ecc.Element, threshold)

	for i := range threshold {
		r.Commitment[i] = g.NewElement()
	}
}

type r2DataShadow Round2Data

func (r *r2DataShadow) init(g ecc.Group, _ uint16) {
	r.Group = g
	r.SecretShare = g.NewScalar()
}

type signatureShadow Signature

func (s *signatureShadow) init(g ecc.Group, _ uint16) {
	s.Group = g
	s.R = g.NewElement()
	s.Z = g.NewScalar()
}

// jsonReCommitmentLen attempts to find the number of elements encoded in the commitment.
func jsonReCommitmentLen(s string) int {
	re := regexp.MustCompile(`commitment":\[\s*(.*?)\s*]`)

	matches := re.FindStringSubmatch(s)
	if len(matches) == 0 {
		return 0
	}

	if matches[1] == "" {
		return 0
	}

	n := strings.Count(matches[1], ",")

	return n + 1
}

func unmarshalJSONHeader(data []byte) (Ciphersuite, uint16, error) {
	s := string(data)

	g, err := jsonReGetGroup(s)
	if err != nil {
		return 0, 0, err
	}

	nPoly := jsonReCommitmentLen(s)
	if nPoly > 65535 {
		return 0, 0, errInvalidPolynomialLength
	}

	return g, uint16(nPoly), nil
}

func unmarshalJSON(data []byte, target shadowInit) error {
	c, nPoly, err := unmarshalJSONHeader(data)
	if err != nil {
		return err
	}

	target.init(ecc.Group(c), nPoly)

	if err = json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}
