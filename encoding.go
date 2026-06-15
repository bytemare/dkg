// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bytemare/ecc"
)

var errInvalidPolynomialLength = errors.New("invalid polynomial length (exceeds uint16 limit 65535)")

type shadowInit interface {
	init(g ecc.Group, threshold uint16)
	group() ecc.Group
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

func (r *r1DataShadow) group() ecc.Group {
	return r.Group
}

type r2DataShadow Round2Data

func (r *r2DataShadow) init(g ecc.Group, _ uint16) {
	r.Group = g
	r.SecretShare = g.NewScalar()
}

func (r *r2DataShadow) group() ecc.Group {
	return r.Group
}

type signatureShadow Signature

func (s *signatureShadow) init(g ecc.Group, _ uint16) {
	s.Group = g
	s.R = g.NewElement()
	s.Z = g.NewScalar()
}

func (s *signatureShadow) group() ecc.Group {
	return s.Group
}

func unmarshalJSONHeader(data []byte) (Ciphersuite, uint16, error) {
	var header struct {
		Group      json.RawMessage   `json:"group"`
		Commitment []json.RawMessage `json:"commitment"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return 0, 0, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	if len(header.Group) == 0 {
		return 0, 0, errEncodingInvalidJSONEncoding
	}

	var group int64
	if err := json.Unmarshal(header.Group, &group); err != nil {
		return 0, 0, fmt.Errorf("failed to read Group: %w", err)
	}

	if group < 0 || group > 63 {
		return 0, 0, errInvalidCiphersuite
	}

	c := Ciphersuite(group)
	if !c.Available() {
		return 0, 0, errInvalidCiphersuite
	}

	if len(header.Commitment) > 65535 {
		return 0, 0, errInvalidPolynomialLength
	}

	if err := validateJSONGroups(data, ecc.Group(c)); err != nil {
		return 0, 0, err
	}

	return c, uint16(len(header.Commitment)), nil
}

func validateJSONGroups(data []byte, expected ecc.Group) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("failed to unmarshal group: %w", err)
	}

	return validateJSONGroupValue(value, expected)
}

func validateJSONGroupValue(value any, expected ecc.Group) error {
	switch current := value.(type) {
	case []any:
		for _, item := range current {
			if err := validateJSONGroupValue(item, expected); err != nil {
				return err
			}
		}
	case map[string]any:
		return validateJSONGroupMap(current, expected)
	}

	return nil
}

func validateJSONGroupMap(value map[string]any, expected ecc.Group) error {
	for key, item := range value {
		if key == "group" {
			group, ok := item.(float64)
			if !ok || group != float64(expected) {
				return errInvalidCiphersuite
			}
		}

		if err := validateJSONGroupValue(item, expected); err != nil {
			return err
		}
	}

	return nil
}

func unmarshalJSON(data []byte, target shadowInit) error {
	c, nPoly, err := unmarshalJSONHeader(data)
	if err != nil {
		return err
	}

	g := ecc.Group(c)
	target.init(g, nPoly)

	if err = json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%w", err)
	}

	if target.group() != g {
		return errInvalidCiphersuite
	}

	return nil
}
