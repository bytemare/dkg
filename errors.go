// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg

import (
	"errors"
)

var (
	errAbortInvalidSignature            = errors.New("ABORT - invalid signature")
	errAbortInvalidSecretShare          = errors.New("ABORT - invalid secret share received from peer")
	errInvalidCiphersuite               = errors.New("invalid ciphersuite")
	errMaxSignersZero                   = errors.New("max signers is 0")
	errParticipantIDZero                = errors.New("identifier is 0")
	errParticipantAlreadyStarted        = errors.New("participant has already started")
	errParticipantAlreadyContinued      = errors.New("participant has already continued")
	errParticipantAlreadyFinalized      = errors.New("participant has already finalized")
	errParticipantNotStarted            = errors.New("participant is not started")
	errParticipantNotContinued          = errors.New("participant is not continued")
	errProofNonceMultiple               = errors.New("only one deterministic nonce is supported")
	errProofNonceNil                    = errors.New("the provided nonce is nil")
	errProofNonceWrongGroup             = errors.New("the provided nonce has incompatible EC group")
	errProofNonceZero                   = errors.New("the provided nonce is zero")
	errProofSecretNil                   = errors.New("the provided secret is nil")
	errProofSecretWrongGroup            = errors.New("the provided secret has incompatible EC group")
	errProofSecretZero                  = errors.New("the provided secret is zero")
	errProofPubKeyIdentity              = errors.New("the provided public key is identity")
	errProofPubKeyMismatch              = errors.New("the provided public key does not match the secret")
	errThresholdZero                    = errors.New("threshold is 0")
	errThresholdAboveMaxSigners         = errors.New("threshold is above max signers")
	errParticipantUninitialized         = errors.New("participant is not initialized")
	errRound1NilPackage                 = errors.New("round 1 data packet is nil")
	errRound1MissingPackage             = errors.New("missing round 1 package from participant")
	errRound1DuplicateSender            = errors.New("duplicate round 1 package from participant")
	errRound2NilPackage                 = errors.New("round 2 data packet is nil")
	errRound2MissingPackage             = errors.New("missing round 2 package from participant")
	errRound2DuplicateSender            = errors.New("duplicate round 2 package from participant")
	errRound1DataElements               = errors.New("invalid number of expected round 1 data packets")
	errRound2DataElements               = errors.New("invalid number of expected round 2 data packets")
	errRound2InvalidReceiver            = errors.New("invalid receiver in round 2 package")
	errRound2OwnPackage                 = errors.New("mixed packages: received a round 2 package from itself")
	errRound2FaultyPackage              = errors.New("malformed Round2Data package: sender and recipient are the same")
	errCommitmentNotFound               = errors.New("commitment not found in Round 1 data for participant")
	errVerificationShareFailed          = errors.New("failed to compute correct verification share")
	errNilPubKey                        = errors.New("the provided public key is nil")
	errMissingCommitment                = errors.New("missing commitment")
	errCommitmentNilElement             = errors.New("commitment has nil element")
	errCommitmentIdentityElement        = errors.New("commitment has identity element")
	errCommitmentWrongGroup             = errors.New("commitment element has incompatible EC group")
	errCommitmentEmpty                  = errors.New("commitment is empty")
	errAggregateCommitmentHighestDegree = errors.New(
		"aggregate commitment has identity commitment for the highest-degree coefficient",
	)
	errRound1CommitmentMismatch           = errors.New("round 1 commitment does not match verified commitment")
	errSecretShareNil                     = errors.New("secret share is nil")
	errSecretShareWrongGroup              = errors.New("secret share has incompatible EC group")
	errPubKeyWrongGroup                   = errors.New("the provided public key has incompatible EC group")
	errPolynomialLength                   = errors.New("invalid polynomial length")
	errDecodeInvalidLength                = errors.New("invalid encoding length")
	errDecodeProofR                       = errors.New("invalid encoding of R proof")
	errDecodeProofZ                       = errors.New("invalid encoding of z proof")
	errDecodeCommitment                   = errors.New("invalid encoding of commitment")
	errDecodeSecretShare                  = errors.New("invalid encoding of secret share")
	errEncodingInvalidLength              = errors.New("invalid encoding length")
	errEncodingInvalidJSONEncoding        = errors.New("invalid JSON encoding")
	errInvalidPolynomialSecretZero        = errors.New("invalid polynomial: the provided secret is zero")
	errInvalidPolynomialHighestDegreeZero = errors.New("invalid polynomial: the highest-degree coefficient is zero")
)

const errWrapperWithID = "%w: %d"
