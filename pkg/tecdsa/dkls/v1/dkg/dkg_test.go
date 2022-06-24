//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkg

import (
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/trysuperdrop/kryptology/pkg/zkp/schnorr"
	"github.com/vmihailenco/msgpack/v5"
	"log"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trysuperdrop/kryptology/pkg/core/curves"
	"github.com/trysuperdrop/kryptology/pkg/ot/extension/kos"
)

func TestDkg(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		boundCurve := curve
		t.Run(
			fmt.Sprintf("testing dkg for curve %s", boundCurve.Name), func(tt *testing.T) {
				tt.Parallel()
				alice := NewAlice(boundCurve)
				bob := NewBob(boundCurve)

				seed, err := bob.Round1GenerateRandomSeed()
				require.NoError(tt, err)
				round3Output, err := alice.Round2CommitToProof(seed)
				require.NoError(tt, err)
				proof, err := bob.Round3SchnorrProve(round3Output)
				require.NoError(tt, err)
				proof, err = alice.Round4VerifyAndReveal(proof)
				require.NoError(tt, err)
				proof, err = bob.Round5DecommitmentAndStartOt(proof)
				require.NoError(tt, err)
				compressedReceiversMaskedChoice, err := alice.Round6DkgRound2Ot(proof)
				require.NoError(tt, err)
				challenge, err := bob.Round7DkgRound3Ot(compressedReceiversMaskedChoice)
				require.NoError(tt, err)
				challengeResponse, err := alice.Round8DkgRound4Ot(challenge)
				require.NoError(tt, err)
				challengeOpenings, err := bob.Round9DkgRound5Ot(challengeResponse)
				require.NoError(tt, err)
				err = alice.Round10DkgRound6Ot(challengeOpenings)
				require.NoError(tt, err)
				// Verify correctness of the OT subprotocol after  has completed
				for i := 0; i < kos.Kappa; i++ {
					if alice.receiver.Output.OneTimePadDecryptionKey[i] != bob.sender.Output.OneTimePadEncryptionKeys[i][alice.receiver.Output.RandomChoiceBits[i]] {
						tt.Errorf("oblivious transfer is incorrect at index i=%v", i)
					}
				}

				pkA := boundCurve.ScalarBaseMult(alice.Output().SecretKeyShare)
				pkB := boundCurve.ScalarBaseMult(bob.Output().SecretKeyShare)

				computedPublicKeyA := pkA.Mul(bob.Output().SecretKeyShare)
				require.True(tt, computedPublicKeyA.Equal(alice.Output().PublicKey))
				require.True(tt, computedPublicKeyA.Equal(bob.Output().PublicKey))

				computedPublicKeyB := pkB.Mul(alice.Output().SecretKeyShare)
				require.True(tt, computedPublicKeyB.Equal(alice.Output().PublicKey))
				require.True(tt, computedPublicKeyB.Equal(bob.Output().PublicKey))
			},
		)
	}
}

func BenchmarkDkg(b *testing.B) {
	if testing.Short() {
		b.SkipNow()
	}
	curve := curves.K256()

	for n := 0; n < b.N; n++ {
		alice := NewAlice(curve)
		bob := NewBob(curve)

		seed, err := bob.Round1GenerateRandomSeed()
		require.NoError(b, err)
		round3Output, err := alice.Round2CommitToProof(seed)
		require.NoError(b, err)
		proof, err := bob.Round3SchnorrProve(round3Output)
		require.NoError(b, err)
		proof, err = alice.Round4VerifyAndReveal(proof)
		require.NoError(b, err)
		proof, err = bob.Round5DecommitmentAndStartOt(proof)
		require.NoError(b, err)
		compressedReceiversMaskedChoice, err := alice.Round6DkgRound2Ot(proof)
		require.NoError(b, err)
		challenge, err := bob.Round7DkgRound3Ot(compressedReceiversMaskedChoice)
		require.NoError(b, err)
		challengeResponse, err := alice.Round8DkgRound4Ot(challenge)
		require.NoError(b, err)
		challengeOpenings, err := bob.Round9DkgRound5Ot(challengeResponse)
		require.NoError(b, err)
		err = alice.Round10DkgRound6Ot(challengeOpenings)
		require.NoError(b, err)
	}
}

type customStruct struct {
	prover         *schnorr.Prover
	curve          *curves.Curve
	secretKeyShare curves.Scalar
}

func (s *customStruct) MarshalBinary() ([]byte, error) {
	var enc *gob.Encoder
	var buf bytes.Buffer

	buf = bytes.Buffer{}
	enc = gob.NewEncoder(&buf)
	marshalData := map[string][]byte{}
	if err := enc.Encode(s.prover); err != nil {
		return nil, err
	}
	marshalData["prover"] = buf.Bytes()

	buf = bytes.Buffer{}
	enc = gob.NewEncoder(&buf)
	if err := enc.Encode(s.curve); err != nil {
		return nil, err
	}
	marshalData["curve"] = buf.Bytes()

	buf = bytes.Buffer{}
	enc = gob.NewEncoder(&buf)
	if err := enc.Encode(&s.secretKeyShare); err != nil {
		return nil, err
	}
	marshalData["secretKeyShare"] = buf.Bytes()

	buf = bytes.Buffer{}
	enc = gob.NewEncoder(&buf)
	if err := enc.Encode(marshalData); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *customStruct) UnmarshalBinary(data []byte) error {
	var reader *bytes.Reader
	var dec *gob.Decoder

	//Use default gob decoder
	reader = bytes.NewReader(data)
	dec = gob.NewDecoder(reader)
	unmarshalData := map[string][]byte{}
	if err := dec.Decode(&unmarshalData); err != nil {
		return err
	}

	reader = bytes.NewReader(unmarshalData["prover"])
	dec = gob.NewDecoder(reader)
	if err := dec.Decode(&s.prover); err != nil {
		return err
	}

	reader = bytes.NewReader(unmarshalData["curve"])
	dec = gob.NewDecoder(reader)
	if err := dec.Decode(&s.curve); err != nil {
		return err
	}

	reader = bytes.NewReader(unmarshalData["secretKeyShare"])
	dec = gob.NewDecoder(reader)
	if err := dec.Decode(&s.secretKeyShare); err != nil {
		return err
	}
	return nil
}

func TestAliceEncode(t *testing.T) {
	gob.Register(&curves.ScalarK256{})
	gob.Register(&curves.PointK256{})
	t.Parallel()
	k256 := curves.K256()
	sc := k256.Scalar.Random(crand.Reader)
	c := &customStruct{
		prover:         schnorr.NewProver(k256, nil, []byte("unique session id random string")),
		curve:          k256,
		secretKeyShare: sc,
	}
	b, err := msgpack.Marshal(c)
	assert.Nil(t, err)
	log.Println(b)

	var v customStruct
	err = msgpack.Unmarshal(b, &v)
	assert.Nil(t, err)
	//assert.Equal(t, curves.K256(), v.curve)
	assert.Equal(t, sc, v.secretKeyShare)
	assert.Equal(t, c, &v)
}
