// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package dkg_test

import (
	"errors"
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/dkg"
)

func testAllCases(t *testing.T, f func(*testCase)) {
	for _, test := range testTable {
		t.Run(test.name, func(t *testing.T) {
			f(test)
		})
	}
}

type testZKVector struct {
	k  string
	sk string
	pk string
	r  string
	z  string
	id uint16
}

type testCase struct {
	name            string
	zk              testZKVector
	threshold       uint16
	maxParticipants uint16
	ciphersuite     dkg.Ciphersuite
	group           group.Group
}

var testTable = []*testCase{
	{
		name:            "Ristretto255 (3,5)",
		ciphersuite:     dkg.Ristretto255Sha512,
		group:           group.Ristretto255Sha512,
		threshold:       3,
		maxParticipants: 5,
		zk: testZKVector{
			id: 1,
			k:  "7a4fc453d0b1db44db80c6c94b994980539689ad98d3e0b51f740eecd5c5060e",
			sk: "d81928ea37fcc34a2df8b17e00d02080a374cd5f4a7a067aaf2d7306b3a83e06",
			pk: "783f503f8c99373b60dad5982b478878ae0dda78fe4485b659d28defa9aded20",
			r:  "c878514445a823fad8bf8def4d5213d39eb5b12d895300a8e2ab17751cb1561d",
			z:  "619e0d45dedab63f2f71d18977fe9588e788570832352549826a6c6cdeebb605",
		},
	},
	{
		name:            "P-256 (3,5)",
		ciphersuite:     dkg.P256Sha256,
		group:           group.P256Sha256,
		threshold:       3,
		maxParticipants: 5,
		zk: testZKVector{
			id: 1,
			k:  "0a866adfedfe222895d04e603ce251322edf1dffde8904be157a4576d314d124",
			sk: "d0b773f5624fc12c88d04897518d97151a6334712e5c3758a6d6d19e8e2b80fe",
			pk: "036a4d7eec05b59453923fab5d031df3bba8cda09f36c76b6595fba8b9a78dd2b1",
			r:  "02867523a2938dec586b1c6a81374d0d9fb0f38987c3b249c45949082035ac911b",
			z:  "e1e59096e5890b6e33feb31eadfd6a9f71b240d7f3cedf5e53db9b47056c94a1",
		},
	},
	{
		name:            "P-384 (3,5)",
		ciphersuite:     dkg.P384Sha384,
		group:           group.P384Sha384,
		threshold:       3,
		maxParticipants: 5,
		zk: testZKVector{
			id: 1,
			k:  "e3bb58be9f48f76c669ddda46295d19bd41e92bbdced9f406b2f92a29db77a9fe63c24bf86825dcd60c394458f166031",
			sk: "cf26e3c89ce69a3f820b9a98a28c4ae1d9cc45c07f8ff87a17a2e392c3d7b7afbd4555c815f7bef69e23524a4311290a",
			pk: "020853239ae4b519de0484cd3c6b0f7116a715f8c4045c99104e8f3ffdbccfdfa1b7ad08093efbed9a73fb68675a0ba5e9",
			r:  "0334f36c69b8e20df93f805dcd21f0c10e48b1d31c913420199aa2166eff8046d59b1054ba664f3546924ade5e9a609adb",
			z:  "15a19c0a52c7967092b93b3182cf6a6cc38b24d8f50e22cc82d23d81a675ea88213685fd7b2e6b8f4ee971afdcdc7b25",
		},
	},
	{
		name:            "P-521 (3,5)",
		ciphersuite:     dkg.P521Sha512,
		group:           group.P521Sha512,
		threshold:       3,
		maxParticipants: 5,
		zk: testZKVector{
			id: 1,
			k:  "01f470f7a16a431ad322e7cd5686832e37067c0faef3e865cc75d5a89b5064ff67dd35d4e8167b9744e36f76929e45e15c9bd28a0f04795a54d524e7e2cccc1f0975",
			sk: "007ef1b7f82934cc84dfdfb381e3bbe7796ee9671d141f304f9fea58ff1aee10ad532461a41cdc8a93553b75523a3a58b9f8aa2abf34891a17b978264c00d09fdc4a",
			pk: "030106e573fc647d49cb4cfeef2c948e62f630a129493b127ebcfd2e25c55e0ed9ec4c82deb94e8bc11abd767a7208e2c4f9617cc42be66cc15d0aa379773129c69398",
			r:  "030119911710bea65e4d0f95aeb20802ae4ad31eaa33c3b830679f0a8948f58895eb37f87f2b1be9243cd5bab54ae127aa252903dc6bed921b072e7400bedba9527700",
			z:  "01c0bbfbed8f5a3ce24b6f3fed96fef63f9ee4b037934bb464aa37366ed05a25f9ec621f5515c4baaf99c6d661ce47830116c8aa3495aed0160c32a5e3892a962ec5",
		},
	},
	{
		name:            "Edwards25519 (3,5)",
		ciphersuite:     dkg.Edwards25519Sha512,
		group:           group.Edwards25519Sha512,
		threshold:       3,
		maxParticipants: 5,
		zk: testZKVector{
			id: 1,
			k:  "6f3206f94ba52e9669fe5e845662ed59fc61726fab37bc4d25803de3c78b2108",
			sk: "25ae4ebd5cab19ac14276562aa22143a8168c5b164ee24f948cd15131351bd02",
			pk: "401d92c813d7fcf2c31b6256b891ba704ff98f42d2f125b1163af46b85be783e",
			r:  "743625068a9c1d4a416e0ff49f476398275e71d69948b1d552586a1c612da912",
			z:  "ae1399bcb59ec84bd93382025d42d4d7b99925e36b60d2b4062965a210409c05",
		},
	},
	{
		name:            "SECp256k1 (3,5)",
		ciphersuite:     dkg.Secp256k1,
		group:           group.Secp256k1,
		threshold:       3,
		maxParticipants: 5,
		zk: testZKVector{
			id: 1,
			k:  "e515f8a3682f1f75422f865d7d60eeaceb528ff9fd4e214d63d0a355e159538c",
			sk: "269ec3ca26bd23258b9878a76524b3e74078e644fae6d66e31b646d898bcd3fd",
			pk: "039824dc4200c34f7d4a714cbecc78b378110af2d5fd6796bfc030a881f03c8a27",
			r:  "03c673d41b16d2d05500ca1563896b495c213199c87a620cd4b6d9e41b7a1c5749",
			z:  "2aff23d11711a9fedcf8c3ffbf8ba16590daa92a9f93af37c40eac1f225abfd7",
		},
	},
}

var (
	errExpectedAvailability       = errors.New("expected ciphersuite availability")
	errUnexpectedAvailability     = errors.New("unexpected ciphersuite availability")
	errUnexpectedCiphersuiteGroup = errors.New("unexpected ciphersuite group")
)
