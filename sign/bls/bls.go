package bls

import (
	"crypto/cipher"
	"errors"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/group/pbc"
)

// XXX ideas or comments for the Suite modularization
// - a bit annoying having to implement Scalar in each group while it's the same
// underlying field
// - NewKeyPair does not when given this suite. Each G1, G2 or GT should
// implement Cipher / Hash factory to be usable. Huge repetition for low gains.
type PairingSuite interface {
	G1() kyber.Group
	G2() kyber.Group
	GT() pbc.PairingGroup
}

type Suite interface {
	PairingSuite
	kyber.HashFactory
	kyber.CipherFactory
}

func NewKeyPair(s Suite, r cipher.Stream) (kyber.Scalar, kyber.Point) {
	sk := s.G2().Scalar().Pick(r)
	pk := s.G2().Point().Mul(sk, nil)
	return sk, pk
}

// Performs a BLS signature operation. Namely, it computes:
//
//   x * H(m) as a point on G1
//
// where x is the private key, and m the message.
func Sign(s Suite, private kyber.Scalar, msg []byte) []byte {
	HM := hashed(s, msg)
	xHM := HM.Mul(private, HM)
	sig, _ := xHM.MarshalBinary()
	return sig
}

// Verify checks the signature. Namely, it checks the equivalence between
//
//  e(H(m),X) == e(H(m), G2^x) == e(H(m)^x, G2) == e(s, G2)
//
// where m is the message, X the public key from G2, s the signature and G2 the base
// point from which the public key have been generated.
func Verify(s Suite, public kyber.Point, msg, sig []byte) error {
	HM := hashed(s, msg)
	left := s.GT().PairingPoint().Pairing(HM, public)
	sigPoint := s.G1().Point()
	if err := sigPoint.UnmarshalBinary(sig); err != nil {
		return err
	}

	g2 := s.G2().Point().Base()
	right := s.GT().PairingPoint().Pairing(sigPoint, g2)

	if !left.Equal(right) {
		return errors.New("bls: invalid signature")
	}
	return nil
}

func hashed(s Suite, msg []byte) kyber.Point {
	hashed := s.Hash().Sum(msg)
	return s.G1().Point().Pick(s.Cipher(hashed))
}
