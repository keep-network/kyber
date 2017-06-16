package bls

import (
	"testing"

	"github.com/stretchr/testify/require"

	"gopkg.in/dedis/kyber.v1/group/pbc"
	"gopkg.in/dedis/kyber.v1/util/random"
)

func TestBLSSig(t *testing.T) {
	s := pbc.NewPairingFp382_1()
	sk, pk := NewKeyPair(s, random.Stream)
	msg := []byte("hello world")

	sig := Sign(s, sk, msg)
	require.Nil(t, Verify(s, pk, msg, sig))

	wrongMsg := []byte("evil message")
	require.Error(t, Verify(s, pk, msg, wrongMsg))
}
