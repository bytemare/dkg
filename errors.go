// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg

import (
	"errors"
)

var (
	errAbortInvalidSignature          = errors.New("ABORT - invalid signature")
	errAbortInvalidSecretShare        = errors.New("ABORT - invalid secret share received from peer")
	errInvalidCiphersuite             = errors.New("invalid ciphersuite")
	errParticipantIDZero              = errors.New("identifier is 0")
	errRound1DataElements             = errors.New("invalid number of expected round 1 data packets")
	errRound2DataElements             = errors.New("invalid number of expected round 2 data packets")
	errRound2InvalidReceiver          = errors.New("invalid receiver in round 2 package")
	errRound2OwnPackage               = errors.New("mixed packages: received a round 2 package from itself")
	errRound2FaultyPackage            = errors.New("malformed Round2Data package: sender and recipient are the same")
	errCommitmentNotFound             = errors.New("commitment not found in Round 1 data for participant")
	errVerificationShareFailed        = errors.New("failed to compute correct verification share")
	errNilPubKey                      = errors.New("the provided public key is nil")
	errMissingCommitments             = errors.New("missing commitments")
	errNoCommitment                   = errors.New("empty commitment")
	errCommitmentNilElement           = errors.New("commitment has nil element")
	errCommitmentEmpty                = errors.New("commitment is empty")
	errPolynomialLength               = errors.New("invalid polynomial length")
	errDecodeNoMessage                = errors.New("no data to decode")
	errDecodeInvalidLength            = errors.New("invalid encoding length")
	errDecodeProofR                   = errors.New("invalid encoding of R proof")
	errDecodeProofZ                   = errors.New("invalid encoding of z proof")
	errDecodeCommitment               = errors.New("invalid encoding of commitment")
	errDecodeSecretShare              = errors.New("invalid encoding of secret share")
	errPublicKeyShareCapacityExceeded = errors.New("can't add another public key share (full capacity)")
	errEncodingInvalidLength          = errors.New("invalid encoding length")
	errEncodingInvalidJSONEncoding    = errors.New("invalid JSON encoding")
	errEncodingPKSDuplication         = errors.New("multiple encoded public key shares with same ID")
	errPublicKeyShareRegistered       = errors.New("the public key share is already registered")
	errRegistryHasNilPublicKey        = errors.New("encountered a nil public key in registry")
	errVerifyBadPubKey                = errors.New("the public key differs from the one registered")
	errVerifyUnknownID                = errors.New("the requested identifier is not registered")
)

const errWrapperWithID = "%w: %d"
