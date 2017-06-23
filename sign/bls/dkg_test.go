package bls

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"gopkg.in/dedis/crypto.v1/util/random"
	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/group/pbc"
)

func TestDKGDeal(test *testing.T) {
	s := pbc.NewPairingFp382_1()

	n := 5
	t := 3

	msg := []byte("Hello World")

	privates := make([]kyber.Scalar, n)
	publics := make([]kyber.Point, n)
	dkgs := make([]*DKG, n)
	deals := make([]*Deals, n)
	partials := make([]*PartialPublic, n)
	collectivesPublic := make([]kyber.Point, n)
	partialSigs := make([]*PartialBLS, n)

	// generate private / public key pairs
	for i := 0; i < n; i++ {
		privates[i], publics[i] = NewKeyPair(s, random.Stream)
	}

	// generate dkgs
	for i := 0; i < n; i++ {
		dkgs[i] = newDKG(s, privates[i], publics[i], publics, i, t)
	}

	// generate deals
	for i := 0; i < n; i++ {
		deals[i] = dkgs[i].Deals()
	}

	// process deals
	for i := 0; i < n; i++ {
		// each dkgs receive all deals
		for j := 0; j < n; j++ {
			err := dkgs[j].ProcessDeals(deals[i])
			require.Nil(test, err)
		}
	}

	// generate partial public keys
	for i := 0; i < n; i++ {
		partials[i] = dkgs[i].RevealPartiaPublic()
	}

	// Process them
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			dkgs[j].ProcessPartialPublic(partials[i])
		}
	}

	// recover collective public key
	for i := 0; i < n; i++ {
		collectivesPublic[i] = dkgs[i].RecoverPublicKey()
	}

	// check equality
	for i := 0; i < n; i++ {
		if !collectivesPublic[i].Equal(collectivesPublic[0]) {
			test.Fatalf("%d vs %d not equal public key", i, 0)
		}
	}

	//  reveal partial signatures
	for i := 0; i < n; i++ {
		partialSigs[i] = dkgs[i].RevealBLSPartial(msg)
	}

	// check signatures
	for i := 0; i < n; i++ {
		// randomize order
		l := rand.Perm(n)
		randomized := make([]*PartialBLS, n)
		for j, h := range l {
			randomized[h] = partialSigs[j]
		}
		require.Nil(test, dkgs[i].VerifySignatures(msg, randomized))
	}

}
