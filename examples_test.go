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

	secretsharing "github.com/bytemare/secret-sharing"

	"github.com/bytemare/dkg"
)

// Example_dkg shows the 3-step 2-message distributed key generation procedure that must be executed by each participant
// to build their secret key share.
func Example_dkg() {
	// Each participant must be set to use the same configuration. We use (3,5) here for the demo, on Ristretto255.
	totalAmountOfParticipants := uint16(5)
	threshold := uint16(3)
	c := dkg.Ristretto255Sha512

	var err error

	// Step 0: Initialise your participant. Each participant must be given an identifier that MUST be unique among
	// all participants. For this example, The participants will have the identifiers 1, 2, 3, 4, and 5.
	participants := make([]*dkg.Participant, totalAmountOfParticipants)
	for id := uint16(1); id <= totalAmountOfParticipants; id++ {
		participants[id-1], err = c.NewParticipant(id, threshold, totalAmountOfParticipants)
		if err != nil {
			panic(err)
		}
	}

	// Step 1: Call Start() on each participant. This will return data that must be broadcast to all other participants
	// over a secure channel, which can be encoded/serialized to send over the network. The proxy coordinator or every
	// participant must compile all these packages so that all have the same set.
	accumulatedRound1DataBytes := make([][]byte, totalAmountOfParticipants)
	for i, p := range participants {
		accumulatedRound1DataBytes[i] = p.Start().Encode()
	}

	// Upon reception of the encoded set, decode each item using NewRound1Data().
	// Each participant, on their end, first creates a receiver and then use that to decode.
	// We use Participant 1 here for the demo.
	p1 := participants[0]
	decodedRound1Data := make([]*dkg.Round1Data, totalAmountOfParticipants)
	for i, data := range accumulatedRound1DataBytes {
		decodedRound1Data[i] = p1.NewRound1Data()
		if err = decodedRound1Data[i].Decode(data); err != nil {
			panic(err)
		}
	}

	// Step 2: Call Continue() on each participant providing them with the compiled decoded data. Each participant will
	// return a map of Round2Data, one for each other participant, which must be sent to the specific peer
	// (not broadcast).
	accumulatedRound2Data := make([]map[uint16]*dkg.Round2Data, totalAmountOfParticipants)
	for i, p := range participants {
		if accumulatedRound2Data[i], err = p.Continue(decodedRound1Data); err != nil {
			panic(err)
		}
	}

	// We'll skip the encoding/decoding part (each Round2Data item can be encoded and send over the network).
	// Step 3: Each participant receives the Round2Data set destined to them (there's a Receiver identifier in each
	// Round2Data item), and then calls Finalize with the Round1 and their Round2 data. This will output the
	// participant's key share, containing its secret, public key share, and the group's public key that can be used for
	// signature verification.
	keyShares := make([]*dkg.KeyShare, totalAmountOfParticipants)
	for i, p := range participants {
		accumulatedRound2DataForParticipant := make([]*dkg.Round2Data, 0, totalAmountOfParticipants)
		for _, r2Data := range accumulatedRound2Data {
			if d := r2Data[p.Identifier]; d != nil && d.RecipientIdentifier == p.Identifier {
				accumulatedRound2DataForParticipant = append(accumulatedRound2DataForParticipant, d)
			}
		}

		if keyShares[i], err = p.Finalize(decodedRound1Data, accumulatedRound2DataForParticipant); err != nil {
			panic(err)
		}
	}

	// Optional: Each participant can extract their public info pks := keyShare.Public() and send it to others
	// or a registry of participants. You can encode the registry for transmission or storage (in byte strings or JSON),
	// and recover it.
	PublicKeyShareRegistry := c.NewPublicKeyShareRegistry(threshold, totalAmountOfParticipants)
	for _, ks := range keyShares {
		// A participant extracts its public key share and sends it to the others or the coordinator.
		pks := ks.Public()

		// Anyone can maintain a registry, and add keys for a setup.
		if err = PublicKeyShareRegistry.Add(pks); err != nil {
			panic(err)
		}
	}

	// Given all the commitments (as found in the Round1 data packages or all PublicKeyShare from all participants),
	// one can verify every public key of the setup.
	commitments := PublicKeyShareRegistry.Commitments()
	for _, pks := range PublicKeyShareRegistry.PublicKeyShares {
		if !pks.Verify(commitments) {
			panic("invalid participant public key share")
		}
	}

	// Optional: There are multiple ways on how you can get the group's public key (the one used for signature validation)
	// 1. Participant's Finalize() function returns a KeyShare, which contains the GroupPublicKey, which can be sent to
	// the coordinator or registry.
	// 2. Using the commitments in the Round1 data, this is convenient during protocol execution.
	// 3. Using the participants' commitments in their public key share, this is convenient after protocol execution.
	groupPublicKey1 := keyShares[0].GroupPublicKey
	groupPublicKey2, err := dkg.GroupPublicKeyFromRound1(c, decodedRound1Data)
	if err != nil {
		panic(err)
	}
	groupPublicKey3, err := dkg.GroupPublicKeyFromCommitments(c, PublicKeyShareRegistry.Commitments())
	if err != nil {
		panic(err)
	}

	if groupPublicKey1.Equal(groupPublicKey2) != 1 || groupPublicKey1.Equal(groupPublicKey3) != 1 {
		panic("group public key recovery failed")
	}

	PublicKeyShareRegistry.GroupPublicKey = groupPublicKey3

	// A registry can be encoded for backup or transmission.
	encodedRegistry := PublicKeyShareRegistry.Encode()
	fmt.Printf("The encoded registry of public keys is %d bytes long.\n", len(encodedRegistry))

	// Optional: This is how a participant can verify any participants public key of the protocol, given all the commitments.
	// This can be done with the Commitments in the Round1 data set or in the collection of public key shares.
	publicKeyShare := keyShares[2].Public()
	if err = dkg.VerifyPublicKey(c, publicKeyShare.ID, publicKeyShare.PublicKey, PublicKeyShareRegistry.Commitments()); err != nil {
		panic(err)
	}

	fmt.Printf("Signing keys for participant set up and valid.")

	// Not recommended, but shown for consistency: if you gather at least threshold amount of secret keys from participants,
	// you can reconstruct the private key, and validate it with the group's public key. In our example, we use only
	// one participant, so the keys are equivalent. In a true setup, you don't want to extract and gather participants'
	// private keys, as it defeats the purpose of a DKG and might expose them.
	g := c.Group()
	keys := make(
		[]secretsharing.Share,
		threshold,
	) // Here you would add the secret keys from the other participants.
	for i, k := range keyShares[:threshold] {
		keys[i] = k
	}

	recombinedSecret, err := secretsharing.CombineShares(g, keys)
	if err != nil {
		panic("failed to reconstruct secret")
	}

	groupPubKey := g.Base().Multiply(recombinedSecret)
	if groupPubKey.Equal(groupPublicKey3) != 1 {
		panic("failed to recover the correct group secret")
	}

	// Output: The encoded registry of public keys is 712 bytes long.
	// Signing keys for participant set up and valid.
}
