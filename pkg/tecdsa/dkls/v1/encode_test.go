package v1

import (
	"encoding/gob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trysuperdrop/kryptology/pkg/core/curves"
	"github.com/trysuperdrop/kryptology/pkg/core/protocol"
	"github.com/trysuperdrop/kryptology/pkg/ot/extension/kos"
	"github.com/trysuperdrop/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/trysuperdrop/kryptology/pkg/zkp/schnorr"
	"github.com/vmihailenco/msgpack/v5"
	"log"
	"testing"
)

// Tests encoding and decoding alice while the protocol runs to complete the signature
func TestAliceProtocolWithEncode(t *testing.T) {
	gob.Register(&curves.ScalarK256{})
	gob.Register(&curves.PointK256{})
	gob.Register(&schnorr.Prover{})
	gob.Register(&schnorr.Proof{})
	t.Parallel()
	k256 := curves.K256()

	var alice *AliceDkg
	bob := NewBobDkg(k256, protocol.Version1)

	var (
		message *protocol.Message
		aErr    error
		bErr    error
	)
	alice = NewAliceDkg(k256, protocol.Version1)
	for aErr != protocol.ErrProtocolFinished || bErr != protocol.ErrProtocolFinished {
		// Crank each protocol forward one iteration
		message, bErr = bob.Next(message)
		if bErr != nil && bErr != protocol.ErrProtocolFinished {
			log.Println(bErr)
			break
		}
		message, aErr = alice.Next(message)
		if aErr != nil && aErr != protocol.ErrProtocolFinished {
			log.Println(aErr)
			break
		}
		data1, err := msgpack.Marshal(alice)
		unmarshalledDkg := &AliceDkg{}
		err = msgpack.Unmarshal(data1, unmarshalledDkg)
		assert.Nil(t, err)
		unmarshalledDkg.SetSteps(protocol.Version1)
		assert.True(t, alice.Alice.Equals(unmarshalledDkg.Alice))
		assert.Equal(t, alice.step, unmarshalledDkg.step)
		assert.Equal(t, alice.protoStepper.step, unmarshalledDkg.protoStepper.step)
		alice = unmarshalledDkg
	}
	for i := 0; i < kos.Kappa; i++ {
		if alice.Alice.Output().SeedOtResult.OneTimePadDecryptionKey[i] != bob.Bob.Output().SeedOtResult.OneTimePadEncryptionKeys[i][alice.Alice.Output().SeedOtResult.RandomChoiceBits[i]] {
			t.Errorf("oblivious transfer is incorrect at index i=%v", i)
		}
	}

	t.Run(
		"Both parties produces identical composite pubkey", func(t *testing.T) {
			require.True(t, alice.Alice.Output().PublicKey.Equal(bob.Bob.Output().PublicKey))
		},
	)

	var aliceResult *dkg.AliceOutput
	var bobResult *dkg.BobOutput
	t.Run(
		"alice produces valid result", func(t *testing.T) {
			// Get the result
			r, err := alice.Result(protocol.Version1)

			// Test
			require.NoError(t, err)
			require.NotNil(t, r)
			aliceResult, err = DecodeAliceDkgResult(r)
			require.NoError(t, err)
		},
	)
	t.Run(
		"bob produces valid result", func(t *testing.T) {
			// Get the result
			r, err := bob.Result(protocol.Version1)

			// Test
			require.NoError(t, err)
			require.NotNil(t, r)
			bobResult, err = DecodeBobDkgResult(r)
			require.NoError(t, err)
		},
	)

	t.Run(
		"alice/bob agree on pubkey", func(t *testing.T) {
			require.Equal(t, aliceResult.PublicKey, bobResult.PublicKey)
		},
	)

}
