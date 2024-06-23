// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg_test

import (
	"fmt"

	group "github.com/bytemare/crypto"
	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/dkg"
)

// Example_dkg shows the 3-step 2-message distributed key generation procedure that must be executed by each participant
// to build their secret key share.
func Example_dkg() {
	// Each participant must be set to use the same configuration. We use (1,1) here for the demo.
	maximumAmountOfParticipants := uint(1)
	threshold := uint(1)
	c := dkg.Ristretto255Sha512

	// Step 1: Initialise your participant. Each participant must be given an identifier that MUST be unique among
	// all participants. For this example, this participant will have id = 1.
	id := uint64(1)
	dkgParticipant, err := c.NewParticipant(id, maximumAmountOfParticipants, threshold)
	if err != nil {
		panic(err)
	}

	// Step 2: Call Start() on each participant. This will return data that must be broadcast to all other participants
	// over a secure channel.
	round1Data := dkgParticipant.Start()
	encodedRound1 := round1Data.Encode()

	// Step 3: First, collect all round1Data from all other participants, and decode them using NewRound1Data().
	// Then call Continue() on each participant providing them with the compiled data.
	decodedRound1 := dkgParticipant.NewRound1Data()
	if err = decodedRound1.Decode(encodedRound1); err != nil {
		panic(err)
	}
	accumulatedRound1Data := make([]*dkg.Round1Data, 0, maximumAmountOfParticipants)
	accumulatedRound1Data = append(accumulatedRound1Data, decodedRound1)

	// This will return a dedicated package round2Data for each other participant that must be sent to them over a secure channel.
	// The intended receiver is specified in round2Data.
	// Execution MUST be aborted upon errors, and not rewound. If this fails you should probably investigate this.
	round2Data, err := dkgParticipant.Continue(accumulatedRound1Data)
	if err != nil {
		panic(err)
	} else if len(round2Data) != len(accumulatedRound1Data)-1 {
		panic("this is just a test, and it failed")
	}

	// encode the individual packets, which need to be sent to the corresponding recipient
	encodedRound2 := make(map[uint64][]byte, len(round2Data))
	for _, r2 := range round2Data {
		encodedRound2[r2.RecipientIdentifier] = r2.Encode()
	}

	// Step 3: First, collect all round2Data from all other participants intended to this participant, and decode them
	// using NewRound2Data().
	// Then call Finalize() on each participant providing the same input as for Continue() and the collected data from the second round.
	accumulatedRound2Data := make([]*dkg.Round2Data, 0, maximumAmountOfParticipants)
	for _, r2 := range encodedRound2 {
		d := dkgParticipant.NewRound2Data()
		if err = d.Decode(r2); err != nil {
			panic(err)
		}

		// If the data is for our participant, we use it.
		if d.RecipientIdentifier == dkgParticipant.Identifier {
			accumulatedRound2Data = append(accumulatedRound2Data, d)
		}
	}

	// This will, for each participant, return their secret key (which is a share of the global secret signing key),
	// the corresponding verification/public key, and the global public key.
	// In case of errors, execution MUST be aborted.
	participantKeys, groupPublicKey, err := dkgParticipant.Finalize(
		accumulatedRound1Data,
		accumulatedRound2Data,
	)
	if err != nil {
		panic(err)
	}

	// Optional: This is how a participant can verify whether their own public key matches the private.
	g := group.Group(c)
	pub := g.Base().Multiply(participantKeys.SecretKey)
	if pub.Equal(participantKeys.PublicKey) != 1 {
		panic("participant's secret and public key don't match")
	}

	// Optional: This is how a participant can verify any participants public key of the protocol, given all the round1Data.
	if err = dkg.VerifyPublicKey(c, id, participantKeys.PublicKey, accumulatedRound1Data); err != nil {
		panic(err)
	}

	fmt.Printf("Signing keys for participant set up and valid.")

	// Not recommended, but shown for consistency: if you gather at least threshold amount of secret keys from participants,
	// you can reconstruct the private key, and validate it with the group's public key. In our example, we use only
	// one participant, so the keys are equivalent. In a true setup, you don't want to extract and gather participants'
	// private keys, as it defeats the purpose of a DKG and might expose them.
	keyShares := []*secretsharing.KeyShare{
		{
			Identifier: id,
			SecretKey:  participantKeys.SecretKey,
		},
		// Here you would add the secret keys from the other participants.
	}

	recombinedSecret, err := secretsharing.Combine(g, keyShares)
	if err != nil {
		panic("failed to reconstruct secret")
	}

	groupPubKey := g.Base().Multiply(recombinedSecret)
	if groupPubKey.Equal(groupPublicKey) != 1 {
		panic("failed to recover the correct group secret")
	}

	// Output: Signing keys for participant set up and valid.
}
