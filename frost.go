// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"filippo.io/edwards25519"
	group "github.com/bytemare/crypto"
	"github.com/bytemare/hash"
	"github.com/gtank/ristretto255"
)

var errSignatureDecodePrefix = errors.New("failed to decode Signature")

// Signature represents a Schnorr signature.
type Signature struct {
	R     *group.Element `json:"r"`
	Z     *group.Scalar  `json:"z"`
	Group group.Group    `json:"group"`
}

// Encode serializes the signature into a byte string.
func (s *Signature) Encode() []byte {
	out := make([]byte, 1, 1+s.Group.ElementLength()+s.Group.ScalarLength())
	out[0] = byte(s.Group)
	out = append(out, s.R.Encode()...)
	out = append(out, s.Z.Encode()...)

	return out
}

// Decode deserializes the compact encoding obtained from Encode(), or returns an error.
func (s *Signature) Decode(data []byte) error {
	if len(data) <= 1 {
		return fmt.Errorf("%w: %w", errSignatureDecodePrefix, errEncodingInvalidLength)
	}

	if !Ciphersuite(data[0]).Available() {
		return fmt.Errorf("%w: %w", errSignatureDecodePrefix, errInvalidCiphersuite)
	}

	g := group.Group(data[0])
	expectedLength := 1 + g.ElementLength() + g.ScalarLength()

	if len(data) != expectedLength {
		return fmt.Errorf("%w: %w", errSignatureDecodePrefix, errEncodingInvalidLength)
	}

	r := g.NewElement()
	if err := r.Decode(data[1 : 1+g.ElementLength()]); err != nil {
		return fmt.Errorf("%w: %w: %w", errSignatureDecodePrefix, errDecodeProofR, err)
	}

	z := g.NewScalar()
	if err := z.Decode(data[1+g.ElementLength():]); err != nil {
		return fmt.Errorf("%w: %w: %w", errSignatureDecodePrefix, errDecodeProofZ, err)
	}

	s.Group = g
	s.R = r
	s.Z = z

	return nil
}

// Hex returns the hexadecimal representation of the byte encoding returned by Encode().
func (s *Signature) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded representation returned by Hex().
func (s *Signature) DecodeHex(h string) error {
	b, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w: %w", errSignatureDecodePrefix, err)
	}

	return s.Decode(b)
}

// UnmarshalJSON decodes data into k, or returns an error.
func (s *Signature) UnmarshalJSON(data []byte) error {
	shadow := new(signatureShadow)
	if err := unmarshalJSON(data, shadow); err != nil {
		return fmt.Errorf("%w: %w", errSignatureDecodePrefix, err)
	}

	*s = Signature(*shadow)

	return nil
}

// Clear overwrites the original values with default ones.
func (s *Signature) Clear() {
	s.R.Identity()
	s.Z.Zero()
}

func challenge(g group.Group, id uint16, pubkey, r *group.Element) *group.Scalar {
	dst := []byte("dkg")
	dstLen := []byte{byte(3)}
	sLen := []byte{byte(g.ScalarLength())}  // fits on a single byte
	eLen := []byte{byte(g.ElementLength())} // fits on a single byte

	// hash (id || dst || φ0 || r), but with single-byte length prefixes
	input := slices.Concat[[]byte](
		sLen, g.NewScalar().SetUInt64(uint64(id)).Encode(),
		dstLen, dst,
		eLen, pubkey.Encode(),
		eLen, r.Encode(),
	)

	var sc *group.Scalar

	switch g {
	case group.Ristretto255Sha512:
		sc = h2ristretto255(slices.Concat[[]byte]([]byte("FROST-RISTRETTO255-SHA512-v1"), dst, input))
	case group.P256Sha256:
		sc = g.HashToScalar(input, slices.Concat[[]byte]([]byte("FROST-P256-SHA256-v1"), dst))
	case group.P384Sha384:
		sc = g.HashToScalar(input, slices.Concat[[]byte]([]byte("FROST-P384-SHA384-v1"), dst))
	case group.P521Sha512:
		sc = g.HashToScalar(input, slices.Concat[[]byte]([]byte("FROST-P521-SHA512-v1"), dst))
	case group.Edwards25519Sha512:
		sc = h2ed25519(slices.Concat[[]byte]([]byte("FROST-ED25519-SHA512-v1"), dst, input))
	case group.Secp256k1:
		sc = g.HashToScalar(input, slices.Concat[[]byte]([]byte("FROST-secp256k1-SHA256-v1"), dst))
	}

	return sc
}

func generateZKProof(g group.Group, id uint16,
	secret *group.Scalar,
	pubkey *group.Element,
	rand ...*group.Scalar,
) *Signature {
	var k *group.Scalar
	if len(rand) != 0 && rand[0] != nil {
		k = rand[0]
	} else {
		k = g.NewScalar().Random()
	}

	r := g.Base().Multiply(k)
	ch := challenge(g, id, pubkey, r)
	mu := k.Add(secret.Copy().Multiply(ch))

	return &Signature{
		Group: g,
		R:     r,
		Z:     mu,
	}
}

// FrostGenerateZeroKnowledgeProof generates a zero-knowledge proof of secret, as defined by the FROST protocol.
// You most probably don't want to set r, which is a random component necessary for the proof, and can safely ignore it.
func FrostGenerateZeroKnowledgeProof(
	c Ciphersuite,
	id uint16,
	secret *group.Scalar,
	pubkey *group.Element,
	rand ...*group.Scalar,
) (*Signature, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	return generateZKProof(group.Group(c), id, secret, pubkey, rand...), nil
}

func verifyZKProof(g group.Group, id uint16, pubkey *group.Element, proof *Signature) bool {
	ch := challenge(g, id, pubkey, proof.R)
	rc := g.Base().
		Multiply(proof.Z).
		Subtract(pubkey.Copy().Multiply(ch))

	return proof.R.Equal(rc) == 1
}

// FrostVerifyZeroKnowledgeProof verifies a proof generated by FrostGenerateZeroKnowledgeProof.
func FrostVerifyZeroKnowledgeProof(c Ciphersuite, id uint16, pubkey *group.Element, proof *Signature) (bool, error) {
	if !c.Available() {
		return false, errInvalidCiphersuite
	}

	return verifyZKProof(group.Group(c), id, pubkey, proof), nil
}

func decodeScalar(g group.Group, b []byte) *group.Scalar {
	s := g.NewScalar()
	_ = s.Decode(b) //nolint:errcheck // Unreachable error: the encoding is from a valid encoder, ensuring correctness.

	return s
}

func h2ristretto255(input []byte) *group.Scalar {
	h := hash.FromCrypto(group.Ristretto255Sha512.HashFunc()).Hash(input)
	s := ristretto255.NewScalar().FromUniformBytes(h)

	return decodeScalar(group.Ristretto255Sha512, s.Encode(nil))
}

func h2ed25519(input []byte) *group.Scalar {
	h := hash.FromCrypto(group.Edwards25519Sha512.HashFunc()).Hash(input)
	s := edwards25519.NewScalar()
	_, _ = s.SetUniformBytes(h) //nolint:errcheck // Unreachable error: h will always be of the right length.

	return decodeScalar(group.Edwards25519Sha512, s.Bytes())
}
