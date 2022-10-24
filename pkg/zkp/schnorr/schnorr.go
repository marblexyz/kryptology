//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package schnorr implements a Schnorr proof, as described and used in Doerner, et al. https://eprint.iacr.org/2018/499.pdf
// see Functionalities 6. it also implements a "committed" version, as described in Functionality 7.
package schnorr

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"github.com/marblexyz/crypto/sha3"
	"github.com/pkg/errors"

	"github.com/marblexyz/kryptology/pkg/core/curves"
)

type Commitment = []byte

type Prover struct {
	curve           *curves.Curve
	basePoint       curves.Point
	uniqueSessionId []byte
}

// Proof contains the (c, s) schnorr proof. `Statement` is the curve point you're proving knowledge of discrete log of,
// with respect to the base point.
type Proof struct {
	C         curves.Scalar
	S         curves.Scalar
	Statement curves.Point
}

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
// We allow the option `basePoint == nil`, in which case `basePoint` is auto-assigned to be the "default" generator for the group.
func NewProver(curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte) *Prover {
	if basepoint == nil {
		basepoint = curve.NewGeneratorPoint()
	}
	return &Prover{
		curve:           curve,
		basePoint:       basepoint,
		uniqueSessionId: uniqueSessionId,
	}
}

// Prove generates and returns a Schnorr proof, given the scalar witness `x`.
// in the process, it will actually also construct the statement (just one curve mult in this case)
func (p *Prover) Prove(x curves.Scalar) (*Proof, error) {
	// assumes that params, and pub are already populated. populates the fields c and s...
	var err error
	result := &Proof{}
	result.Statement = p.basePoint.Mul(x)
	k := p.curve.Scalar.Random(rand.Reader)
	random := p.basePoint.Mul(k)
	hash := sha3.New256()
	if _, err = hash.Write(p.uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "writing salt to hash in schnorr prove")
	}
	if _, err = hash.Write(p.basePoint.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint to hash in schnorr prove")
	}
	if _, err = hash.Write(result.Statement.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement to hash in schnorr prove")
	}
	if _, err = hash.Write(random.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K to hash in schnorr prove")
	}
	result.C, err = p.curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "writing point K to hash in schnorr prove")
	}
	result.S = result.C.Mul(x).Add(k)
	return result, nil
}

func (s *Prover) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(s.curve); err != nil {
		return nil, err
	}
	if err := enc.Encode(&s.basePoint); err != nil {
		return nil, err
	}
	if err := enc.Encode(s.uniqueSessionId); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Prover) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&s.curve); err != nil {
		return err
	}
	if err := dec.Decode(&s.basePoint); err != nil {
		return err
	}
	if err := dec.Decode(&s.uniqueSessionId); err != nil {
		return err
	}
	return nil
}

// JS TODO Test
func (s *Prover) Equals(cmp *Prover) bool {
	if !s.curve.Equals(*cmp.curve) {
		return false
	}
	if !s.basePoint.Equal(cmp.basePoint) {
		return false
	}
	res := bytes.Compare(s.uniqueSessionId, cmp.uniqueSessionId)
	return res == 0
}

func (s *Proof) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(&s.C); err != nil {
		return nil, err
	}
	if err := enc.Encode(&s.S); err != nil {
		return nil, err
	}
	if err := enc.Encode(&s.Statement); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *Proof) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	dec := gob.NewDecoder(reader)
	if err := dec.Decode(&s.C); err != nil {
		return err
	}
	if err := dec.Decode(&s.S); err != nil {
		return err
	}
	if err := dec.Decode(&s.Statement); err != nil {
		return err
	}
	return nil
}

func (s *Proof) Equals(cmp *Proof) bool {
	if s.C.Cmp(cmp.C) != 0 {
		return false
	}
	if s.S.Cmp(cmp.S) != 0 {
		return false
	}
	if !s.Statement.Equal(cmp.Statement) {
		return false
	}
	return true
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve`.
// As for the prover, we allow `basePoint == nil`, in this case, it's auto-assigned to be the group's default generator.
func Verify(proof *Proof, curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte) error {
	if basepoint == nil {
		basepoint = curve.NewGeneratorPoint()
	}
	gs := basepoint.Mul(proof.S)
	xc := proof.Statement.Mul(proof.C.Neg())
	random := gs.Add(xc)
	hash := sha3.New256()
	if _, err := hash.Write(uniqueSessionId); err != nil {
		return errors.Wrap(err, "writing salt to hash in schnorr verify")
	}
	if _, err := hash.Write(basepoint.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing basePoint to hash in schnorr verify")
	}
	if _, err := hash.Write(proof.Statement.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing statement to hash in schnorr verify")
	}
	if _, err := hash.Write(random.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point K to hash in schnorr verify")
	}
	if subtle.ConstantTimeCompare(proof.C.Bytes(), hash.Sum(nil)) != 1 {
		return fmt.Errorf("schnorr verification failed")
	}
	return nil
}

// ProveCommit generates _and_ commits to a schnorr proof which is later revealed; see Functionality 7.
// returns the Proof and Commitment.
func (p *Prover) ProveCommit(x curves.Scalar) (*Proof, Commitment, error) {
	proof, err := p.Prove(x)
	if err != nil {
		return nil, nil, err
	}
	hash := sha3.New256()
	if _, err = hash.Write(proof.C.Bytes()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.S.Bytes()); err != nil {
		return nil, nil, err
	}
	return proof, hash.Sum(nil), nil
}

// DecommitVerify receives a `Proof` and a `Commitment`; it first checks that the proof actually opens the commitment;
// then it verifies the proof. returns and error if either on eof thse fail.
func DecommitVerify(
	proof *Proof, commitment Commitment, curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte,
) error {
	hash := sha3.New256()
	if _, err := hash.Write(proof.C.Bytes()); err != nil {
		return err
	}
	if _, err := hash.Write(proof.S.Bytes()); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), commitment) != 1 {
		return fmt.Errorf("initial hash decommitment failed")
	}
	return Verify(proof, curve, basepoint, uniqueSessionId)
}
