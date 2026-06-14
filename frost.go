// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
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
	"github.com/bytemare/ecc"
	"github.com/bytemare/hash"
	"github.com/gtank/ristretto255"
)

var errSignatureDecodePrefix = errors.New("failed to decode Signature")

// Signature represents a Schnorr signature.
type Signature struct {
	R     *ecc.Element `json:"r"`
	Z     *ecc.Scalar  `json:"z"`
	Group ecc.Group    `json:"group"`
}

// Encode serializes the signature into a byte string. It returns nil for nil or malformed values.
func (s *Signature) Encode() []byte {
	if s == nil || !s.Group.Available() || s.R == nil || s.Z == nil {
		return nil
	}

	if !elementInGroup(s.R, s.Group) || !scalarInGroup(s.Z, s.Group) {
		return nil
	}

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

	g := ecc.Group(data[0])
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

// Hex returns the hexadecimal representation of the byte encoding returned by Encode(). It returns an empty string when
// Encode returns nil.
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

// Clear overwrites the original values with default ones. It is a no-op for nil or malformed signatures.
func (s *Signature) Clear() {
	if s == nil || !s.Group.Available() || s.R == nil || s.Z == nil {
		return
	}

	if !elementInGroup(s.R, s.Group) || !scalarInGroup(s.Z, s.Group) {
		return
	}

	s.R.Identity()
	s.Z.Zero()
}

func challenge(g ecc.Group, id uint16, pubkey, r *ecc.Element) *ecc.Scalar {
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

	var dstPrefix []byte

	switch g {
	case ecc.Ristretto255Sha512:
		dstPrefix = []byte("FROST-RISTRETTO255-SHA512-v1")
	case ecc.P256Sha256:
		dstPrefix = []byte("FROST-P256-SHA256-v1")
	case ecc.P384Sha384:
		dstPrefix = []byte("FROST-P384-SHA384-v1")
	case ecc.P521Sha512:
		dstPrefix = []byte("FROST-P521-SHA512-v1")
	case ecc.Edwards25519Sha512:
		dstPrefix = []byte("FROST-ED25519-SHA512-v1")
	case ecc.Secp256k1Sha256:
		dstPrefix = []byte("FROST-secp256k1-SHA256-v1")
	}

	var (
		sc  *ecc.Scalar
		err error
	)

	switch g {
	case ecc.Ristretto255Sha512:
		sc = h2ristretto255(slices.Concat[[]byte](dstPrefix, dst, input))
	case ecc.Edwards25519Sha512:
		sc = h2ed25519(slices.Concat[[]byte](dstPrefix, dst, input))
	default:
		sc, err = g.HashToScalar(input, slices.Concat[[]byte](dstPrefix, dst))
		if err != nil {
			panic(
				fmt.Errorf(
					"unexpected error in hashing to scalar in group %d with dstPrefix %q and dst %q: %w",
					g,
					string(dstPrefix),
					string(dst),
					err,
				),
			)
		}
	}

	return sc
}

func validateZKProofInputs(g ecc.Group, id uint16, secret *ecc.Scalar, pubkey *ecc.Element, rand ...*ecc.Scalar) error {
	if err := checkParticipantID(id, 0); err != nil {
		return err
	}

	if secret == nil {
		return errProofSecretNil
	}

	if !scalarInGroup(secret, g) {
		return errProofSecretWrongGroup
	}

	if secret.IsZero() {
		return errProofSecretZero
	}

	if pubkey == nil {
		return errNilPubKey
	}

	if !elementInGroup(pubkey, g) {
		return errPubKeyWrongGroup
	}

	if pubkey.IsIdentity() {
		return errProofPubKeyIdentity
	}

	expectedPubKey := g.Base().Multiply(secret.Copy())
	if !expectedPubKey.Equal(pubkey) {
		return errProofPubKeyMismatch
	}

	if len(rand) > 1 {
		return errProofNonceMultiple
	}

	if len(rand) == 1 {
		nonce := rand[0]
		if nonce == nil {
			return errProofNonceNil
		}

		if !scalarInGroup(nonce, g) {
			return errProofNonceWrongGroup
		}

		if nonce.IsZero() {
			return errProofNonceZero
		}
	}

	return nil
}

func generateZKProof(g ecc.Group, id uint16,
	secret *ecc.Scalar,
	pubkey *ecc.Element,
	rand ...*ecc.Scalar,
) (*Signature, error) {
	if err := validateZKProofInputs(g, id, secret, pubkey, rand...); err != nil {
		return nil, err
	}

	var k *ecc.Scalar
	if len(rand) == 1 {
		k = rand[0]
	} else {
		for {
			k = g.NewScalar().Random()
			if !k.IsZero() {
				break
			}
		}
	}

	r := g.Base().Multiply(k)
	ch := challenge(g, id, pubkey, r)
	mu := k.Copy().Add(secret.Copy().Multiply(ch))

	return &Signature{
		Group: g,
		R:     r,
		Z:     mu,
	}, nil
}

// FrostGenerateZeroKnowledgeProof generates a zero-knowledge proof of secret, as defined by the FROST protocol.
// Omit rand in normal use. If provided, exactly one rand value is accepted; it is the Schnorr proof nonce and must stay
// secret and be unique for a given secret across distinct challenges, because reuse or disclosure can leak the secret.
func FrostGenerateZeroKnowledgeProof(
	c Ciphersuite,
	id uint16,
	secret *ecc.Scalar,
	pubkey *ecc.Element,
	rand ...*ecc.Scalar,
) (*Signature, error) {
	if !c.Available() {
		return nil, errInvalidCiphersuite
	}

	return generateZKProof(ecc.Group(c), id, secret, pubkey, rand...)
}

func verifyZKProof(g ecc.Group, id uint16, pubkey *ecc.Element, proof *Signature) bool {
	if err := checkParticipantID(id, 0); err != nil {
		return false
	}

	if pubkey == nil || proof == nil || proof.R == nil || proof.Z == nil {
		return false
	}

	if !elementInGroup(pubkey, g) || !elementInGroup(proof.R, g) || !scalarInGroup(proof.Z, g) {
		return false
	}

	if pubkey.IsIdentity() || proof.R.IsIdentity() {
		return false
	}

	ch := challenge(g, id, pubkey, proof.R)
	rc := g.Base().
		Multiply(proof.Z).
		Subtract(pubkey.Copy().Multiply(ch))

	return proof.R.Equal(rc)
}

// FrostVerifyZeroKnowledgeProof verifies a proof generated by FrostGenerateZeroKnowledgeProof.
func FrostVerifyZeroKnowledgeProof(c Ciphersuite, id uint16, pubkey *ecc.Element, proof *Signature) (bool, error) {
	if !c.Available() {
		return false, errInvalidCiphersuite
	}

	if err := checkParticipantID(id, 0); err != nil {
		return false, err
	}

	return verifyZKProof(ecc.Group(c), id, pubkey, proof), nil
}

func decodeScalar(g ecc.Group, b []byte) *ecc.Scalar {
	s := g.NewScalar()
	_ = s.Decode(b) //nolint:errcheck // Unreachable error: the encoding is from a valid encoder, ensuring correctness.

	return s
}

func h2ristretto255(input []byte) *ecc.Scalar {
	h := hash.FromCrypto(ecc.Ristretto255Sha512.HashFunc()).Hash(input)
	s, _ := ristretto255.NewScalar().SetUniformBytes(h) //nolint:errcheck // Unreachable error: HashFunc will always be of the right length.

	return decodeScalar(ecc.Ristretto255Sha512, s.Bytes())
}

func h2ed25519(input []byte) *ecc.Scalar {
	h := hash.FromCrypto(ecc.Edwards25519Sha512.HashFunc()).Hash(input)
	s := edwards25519.NewScalar()
	_, _ = s.SetUniformBytes(h) //nolint:errcheck // Unreachable error: h will always be of the right length.

	return decodeScalar(ecc.Edwards25519Sha512, s.Bytes())
}
