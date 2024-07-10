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
	// Each participant must be set to use the same configuration. We use (3,5) here for the demo.
	maximumAmountOfParticipants := uint(5)
	threshold := uint(3)
	c := dkg.Ristretto255Sha512

	var err error

	// Step 0: Initialise your participant. Each participant must be given an identifier that MUST be unique among
	// all participants. For this example, The participants will have the identifiers 1, 2, 3, 4, and 5.
	participants := make([]*dkg.Participant, maximumAmountOfParticipants)
	for id := uint(1); id <= maximumAmountOfParticipants; id++ {
		participants[id-1], err = c.NewParticipant(uint64(id), maximumAmountOfParticipants, threshold)
		if err != nil {
			panic(err)
		}
	}

	// Step 1: Call Start() on each participant. This will return data that must be broadcast to all other participants
	// over a secure channel, which can be encoded/serialized to send over the network. The proxy coordinator or every
	// participant must compile all these packages so that all have the same set.
	accumulatedRound1DataBytes := make([][]byte, maximumAmountOfParticipants)
	for i, p := range participants {
		accumulatedRound1DataBytes[i] = p.Start().Encode()
	}

	// Upon reception of the encoded set, decode each item using NewRound1Data().
	// Each participant, on their end, first creates a receiver and then use that to decode.
	// We use Participant 1 here for the demo.
	p1 := participants[0]
	decodedRound1Data := make([]*dkg.Round1Data, maximumAmountOfParticipants)
	for i, data := range accumulatedRound1DataBytes {
		decodedRound1Data[i] = p1.NewRound1Data()
		if err = decodedRound1Data[i].Decode(data); err != nil {
			panic(err)
		}
	}

	// Step 2: Call Continue() on each participant providing them with the compiled decoded data. Each participant will
	// return a map of Round2Data, one for each other participant, which must be sent to the specific peer
	// (not broadcast).
	accumulatedRound2Data := make([]map[uint64]*dkg.Round2Data, maximumAmountOfParticipants)
	for i, p := range participants {
		if accumulatedRound2Data[i], err = p.Continue(decodedRound1Data); err != nil {
			panic(err)
		}
	}

	// We'll skip the encoding/decoding part (each Round2Data item can be encoded and send over the network).
	// Step 3: Each participant receives the Round2Data set destined to them (there's a Receiver identifier in each
	// Round2Data item), and then calls Finalize with the Round1 and their Round2 data. This will output the
	// participant's key share and the group's public key that can be used for signature verification.
	keyShares := make([]*dkg.KeyShare, maximumAmountOfParticipants)
	var groupPublicKey *group.Element
	for i, p := range participants {
		accumulatedRound2DataForParticipant := make([]*dkg.Round2Data, 0, maximumAmountOfParticipants)
		for _, r2Data := range accumulatedRound2Data {
			if d := r2Data[p.Identifier]; d != nil && d.RecipientIdentifier == p.Identifier {
				accumulatedRound2DataForParticipant = append(accumulatedRound2DataForParticipant, d)
			}
		}

		if keyShares[i], groupPublicKey, err = p.Finalize(decodedRound1Data, accumulatedRound2DataForParticipant); err != nil {
			panic(err)
		}
	}

	// Optional: This is how a participant can verify whether their own public key matches the private.
	g := group.Group(c)
	pub := g.Base().Multiply(keyShares[0].Secret)
	if pub.Equal(keyShares[0].PublicKey) != 1 {
		panic("participant's secret and public key don't match")
	}

	// Optional: This is how a participant can verify any participants public key of the protocol, given all the round1Data.
	participantID := keyShares[2].PublicKeyShare.ID
	participantPublicKey := keyShares[2].PublicKeyShare.PublicKey
	if err = dkg.VerifyPublicKey(c, participantID, participantPublicKey, decodedRound1Data); err != nil {
		panic(err)
	}

	fmt.Printf("Signing keys for participant set up and valid.")

	// Not recommended, but shown for consistency: if you gather at least threshold amount of secret keys from participants,
	// you can reconstruct the private key, and validate it with the group's public key. In our example, we use only
	// one participant, so the keys are equivalent. In a true setup, you don't want to extract and gather participants'
	// private keys, as it defeats the purpose of a DKG and might expose them.
	keys := make(
		[]secretsharing.Share,
		maximumAmountOfParticipants,
	) // Here you would add the secret keys from the other participants.
	for i, k := range keyShares {
		keys[i] = k
	}

	recombinedSecret, err := secretsharing.CombineShares(g, keys)
	if err != nil {
		panic("failed to reconstruct secret")
	}

	groupPubKey := g.Base().Multiply(recombinedSecret)
	if groupPubKey.Equal(groupPublicKey) != 1 {
		panic("failed to recover the correct group secret")
	}

	// Output: Signing keys for participant set up and valid.
}
