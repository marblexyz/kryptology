package schnorr

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trysuperdrop/crypto/sha3"

	"github.com/trysuperdrop/kryptology/pkg/core/curves"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	gob.Register(&curves.ScalarK256{})
	gob.Register(&curves.PointK256{})
	gob.Register(&curves.ScalarP256{})
	gob.Register(&curves.PointP256{})

	curveInstances := []*curves.Curve{
		curves.K256(),
		// TODO: the code fails on the following curves. Investigate if this is expected.
		//curves.P256(),
		// curves.PALLAS(),
		// curves.BLS12377G1(),
		// curves.BLS12377G2(),
		// curves.BLS12381G1(),
		// curves.BLS12381G2(),
		// curves.ED25519(),
	}
	for i, curve := range curveInstances {
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover := NewProver(curve, nil, uniqueSessionId)

		data, err := prover.MarshalBinary()
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
		data2, err := prover.MarshalBinary()
		assert.Equal(t, data, data2)

		prover2 := &Prover{}
		err = prover2.UnmarshalBinary(data)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
		require.True(t, prover.Equals(prover2))

		secret := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(secret)
		data, err = proof.MarshalBinary()
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		data2, err = proof.MarshalBinary()
		assert.Equal(t, data, data2)

		proof2 := &Proof{}
		err = proof2.UnmarshalBinary(data)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		require.True(t, proof.Equals(proof2))
		err = Verify(proof, curve, nil, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
