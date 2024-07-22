// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package dkg implements the Distributed Key Generation described in FROST,
// using zero-knowledge proofs in Schnorr signatures.
package dkg

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"
)

// KeyShare identifies the sharded key share for a given participant.
type KeyShare secretsharing.KeyShare

// Identifier returns the identity for this share.
func (k *KeyShare) Identifier() uint64 {
	return (*secretsharing.KeyShare)(k).Identifier()
}

// SecretKey returns the participant's secret share.
func (k *KeyShare) SecretKey() *group.Scalar {
	return (*secretsharing.KeyShare)(k).SecretKey()
}

// Public returns the public key share and identifier corresponding to the secret key share.
func (k *KeyShare) Public() *PublicKeyShare {
	return (*PublicKeyShare)(&k.PublicKeyShare)
}

// Encode serializes k into a compact byte string.
func (k *KeyShare) Encode() []byte {
	return (*secretsharing.KeyShare)(k).Encode()
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (k *KeyShare) Decode(data []byte) error {
	if err := (*secretsharing.KeyShare)(k).Decode(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// UnmarshalJSON decodes data into k, or returns an error.
func (k *KeyShare) UnmarshalJSON(data []byte) error {
	if err := (*secretsharing.KeyShare)(k).UnmarshalJSON(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// PublicKeyShare specifies the public key of a participant identified with ID.
type PublicKeyShare secretsharing.PublicKeyShare

// Verify returns whether the PublicKeyShare's public key is valid given its VSS commitment to the secret polynomial.
func (p *PublicKeyShare) Verify(commitments [][]*group.Element) bool {
	return VerifyPublicKey(Ciphersuite(p.Group), p.ID, p.PublicKey, commitments) == nil
}

// Encode serializes p into a compact byte string.
func (p *PublicKeyShare) Encode() []byte {
	return (*secretsharing.PublicKeyShare)(p).Encode()
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (p *PublicKeyShare) Decode(data []byte) error {
	if err := (*secretsharing.PublicKeyShare)(p).Decode(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// UnmarshalJSON decodes data into p, or returns an error.
func (p *PublicKeyShare) UnmarshalJSON(data []byte) error {
	if err := (*secretsharing.PublicKeyShare)(p).UnmarshalJSON(data); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// PublicKeyShareRegistry regroups the final public information about key shares and participants, enabling a registry
// and public key verifications.
type PublicKeyShareRegistry struct {
	GroupPublicKey  *group.Element             `json:"groupPublicKey"`
	PublicKeyShares map[uint64]*PublicKeyShare `json:"publicKeyShares"`
	Total           uint                       `json:"total"`
	Threshold       uint                       `json:"threshold"`
	Ciphersuite     Ciphersuite                `json:"ciphersuite"`
}

// NewPublicKeyShareRegistry returns a populated PublicKeyShareRegistry.
func (c Ciphersuite) NewPublicKeyShareRegistry(threshold, total uint) *PublicKeyShareRegistry {
	return &PublicKeyShareRegistry{
		Ciphersuite:     c,
		Threshold:       threshold,
		Total:           total,
		GroupPublicKey:  nil,
		PublicKeyShares: make(map[uint64]*PublicKeyShare, total),
	}
}

// Add adds the PublicKeyShare to the registry if it's not full or no key for the identifier is already set,
// in which case an error is returned.
func (k *PublicKeyShareRegistry) Add(pks *PublicKeyShare) error {
	if uint(len(k.PublicKeyShares)) == k.Total {
		return errPublicKeyShareCapacityExceeded
	}

	if _, ok := k.PublicKeyShares[pks.ID]; ok {
		return errPublicKeyShareRegistered
	}

	k.PublicKeyShares[pks.ID] = pks

	return nil
}

// Get returns the registered public key for id, or nil.
func (k *PublicKeyShareRegistry) Get(id uint64) *PublicKeyShare {
	for _, pks := range k.PublicKeyShares {
		if pks != nil && pks.ID == id {
			return pks
		}
	}

	return nil
}

// Commitments returns all the commitments for all registered PublicKeyShares.
func (k *PublicKeyShareRegistry) Commitments() [][]*group.Element {
	c := make([][]*group.Element, 0, len(k.PublicKeyShares))

	for _, d := range k.PublicKeyShares {
		c = append(c, d.Commitment)
	}

	return c
}

// VerifyPublicKey returns nil the id / pubKey pair is registered, and an error otherwise.
func (k *PublicKeyShareRegistry) VerifyPublicKey(id uint64, pubKey *group.Element) error {
	for _, ks := range k.PublicKeyShares {
		if ks.ID == id {
			if pubKey == nil {
				return errNilPubKey
			}

			if ks.PublicKey == nil {
				return fmt.Errorf("%w for ID %d", errRegistryHasNilPublicKey, id)
			}

			if ks.PublicKey.Equal(pubKey) != 1 {
				return fmt.Errorf("%w for %d", errVerifyBadPubKey, id)
			}

			return nil
		}
	}

	return fmt.Errorf("%w: %q", errVerifyUnknownID, id)
}

func registerByteSize(c Ciphersuite, threshold, total uint) (int, int) {
	g := group.Group(c)
	eLen := g.ElementLength()
	pksLen := 1 + 8 + 4 + eLen + int(threshold)*eLen

	return 1 + 2 + 2 + g.ElementLength() + int(total)*pksLen, pksLen
}

// Encode serializes the registry into a compact byte encoding of the registry, suitable for storage or transmissions.
func (k *PublicKeyShareRegistry) Encode() []byte {
	size, _ := registerByteSize(k.Ciphersuite, k.Threshold, k.Total)
	out := make([]byte, 5, size)
	out[0] = byte(k.Ciphersuite)
	binary.LittleEndian.PutUint16(out[1:3], uint16(k.Total))
	binary.LittleEndian.PutUint16(out[3:5], uint16(k.Threshold))
	out = append(out, k.GroupPublicKey.Encode()...)

	for _, pks := range k.PublicKeyShares {
		out = append(out, pks.Encode()...)
	}

	if len(out) != size {
		panic(errRegistryEncodingUnexpectedLength)
	}

	return out
}

// Decode deserializes the input data into the registry, expected the same encoding as used in Encode(). It doesn't
// modify the receiver when encountering an error.
func (k *PublicKeyShareRegistry) Decode(data []byte) error {
	if len(data) < 5 {
		return errEncodingInvalidLength
	}

	c := Ciphersuite(data[0])
	if !c.Available() {
		return errInvalidCiphersuite
	}

	total := uint(binary.LittleEndian.Uint16(data[1:3]))
	threshold := uint(binary.LittleEndian.Uint16(data[3:5]))
	size, pksLen := registerByteSize(c, threshold, total)

	if len(data) != size {
		return errEncodingInvalidLength
	}

	g := group.Group(c)
	eLen := g.ElementLength()

	gpk := g.NewElement()
	if err := gpk.Decode(data[5 : 5+eLen]); err != nil {
		return fmt.Errorf("invalid group public key encoding: %w", err)
	}

	pks := make(map[uint64]*PublicKeyShare, total)
	offset := 5 + eLen

	for i := range total {
		pk := new(PublicKeyShare)
		if err := pk.Decode(data[offset : offset+pksLen]); err != nil {
			return fmt.Errorf("could not decode public key share %d: %w", i+1, err)
		}

		if _, ok := pks[pk.ID]; ok {
			return errEncodingPKSDuplication
		}

		pks[pk.ID] = pk
		offset += pksLen
	}

	k.Ciphersuite = c
	k.Total = total
	k.Threshold = threshold
	k.GroupPublicKey = gpk
	k.PublicKeyShares = pks

	return nil
}

type registerShadow PublicKeyShareRegistry

// UnmarshalJSON reads the input data as JSON and deserializes it into the receiver. It doesn't modify the receiver when
// encountering an error.
func (k *PublicKeyShareRegistry) UnmarshalJSON(data []byte) error {
	s := string(data)

	c, err := jsonReGetGroup(s)
	if err != nil {
		return err
	}

	r := new(registerShadow)
	r.GroupPublicKey = group.Group(c).NewElement()

	if err = json.Unmarshal(data, r); err != nil {
		return fmt.Errorf("%w", err)
	}

	*k = PublicKeyShareRegistry(*r)

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
	f, err := jsonReGetField("ciphersuite", s, `(\w+)`)
	if err != nil {
		return 0, err
	}

	i, err := strconv.Atoi(f)
	if err != nil {
		// This can't happen because of JSON's preprocessing checks.
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
