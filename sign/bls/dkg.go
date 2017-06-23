package bls

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/share"
	"gopkg.in/dedis/kyber.v1/util/random"
)

var P_Seed = []byte("Hello World")

type DKG struct {
	suite Suite

	// In Z_l
	secret kyber.Scalar
	// In G_2
	public       kyber.Point
	participants []kyber.Point
	index        int

	t int

	// f polynomial
	f *share.PriPoly
	F *share.PubPoly
	// f' polynomial
	f_ *share.PriPoly
	F_ *share.PubPoly

	// A = F + F'
	A *share.PubPoly

	// base point of F'
	P_ kyber.Point

	// protected share
	xS kyber.Point

	// partials share-public keys g^x_i
	partials []*share.PubShare

	// share - public key
	g_x_i kyber.Point

	// collective public key in GT
	g_x kyber.Point
}

type Deal struct {
	// Index of the recipient
	Index int
	// x_i * S_i
	xS kyber.Point
	// x_i' * S_i
	xS_ kyber.Point
}

type Deals struct {
	// Index of the dealer
	Index int
	// Commitments of A = F + F'
	Commitments []kyber.Point
	Deals       []*Deal
}

type PartialPublic share.PubShare

type PartialBLS struct {
	// index of the issuer
	Index int
	// partial signature
	Signature kyber.Point
	// encrypted share (here for convenience)
	C kyber.Point
}

func newDKG(s Suite, secret kyber.Scalar, public kyber.Point, participants []kyber.Point, i, t int) *DKG {
	dkg := &DKG{
		suite:        s,
		index:        i,
		secret:       secret,
		public:       public,
		participants: participants,
		t:            t,
		P_:           s.G1().Point().Pick(s.Cipher(P_Seed)),
		xS:           s.G2().Point().Null(),
	}
	random_f := s.G1().Scalar().Pick(random.Stream)
	random_f_ := s.G1().Scalar().Pick(random.Stream)

	// f poly
	dkg.f = share.NewPriPoly(s.G1(), t, random_f, random.Stream)
	// f' poly
	dkg.f_ = share.NewPriPoly(s.G1(), t, random_f_, random.Stream)
	// F poly with P = G1's base
	dkg.F = dkg.f.Commit(dkg.suite.G1().Point().Base())
	// F' poly with P' = P_
	dkg.F_ = dkg.f_.Commit(dkg.P_)
	var err error
	dkg.A, err = dkg.F.Add(dkg.F_)
	if err != nil {
		panic(err)
	}
	return dkg
}

func (d *DKG) Deals() *Deals {
	var deals []*Deal
	_, commitments := d.A.Info()
	for i, p := range d.participants {
		if d.index == i {
			continue
		}
		x_i := d.f.Eval(i).V
		x_i_p := d.f_.Eval(i).V
		xS := p.Clone().Mul(x_i, p)
		xS_ := p.Clone().Mul(x_i_p, p)
		deals = append(deals, &Deal{
			Index: i,
			xS:    xS,
			xS_:   xS_,
		})
	}
	return &Deals{
		Index:       d.index,
		Commitments: commitments,
		Deals:       deals,
	}
}

func (d *DKG) processDeal(deal *Deal, commitments []kyber.Point) error {
	// e(P, xS)
	lhs := d.suite.GT().PointGT().Pairing(d.suite.G1().Point().Base(), deal.xS)
	// e(P', x' S)
	rhs := d.suite.GT().PointGT().Pairing(d.P_, deal.xS_)
	left := d.suite.GT().PointGT().Add(lhs, rhs)

	var pairedCommits []kyber.Point
	for _, c := range commitments {
		gt := d.suite.GT().PointGT()
		public := d.participants[deal.Index]
		rhs := gt.Pairing(c, public)
		pairedCommits = append(pairedCommits, rhs)
	}

	// the base is false but not used anyway
	pubPoly := share.NewPubPoly(d.suite.GT(), d.suite.GT().Point().Base(), pairedCommits)
	right := pubPoly.Eval(deal.Index).V

	if !right.Equal(left) {
		return errors.New("pairing deal do not match")
	}

	if deal.Index == d.index {
		// add all protected shares
		d.xS = d.xS.Add(d.xS, deal.xS)
	}
	return nil
}

func (d *DKG) ProcessDeals(deals *Deals) error {
	for _, deal := range deals.Deals {
		if err := d.processDeal(deal, deals.Commitments); err != nil {
			return err
		}
	}
	return nil
}

func (d *DKG) RevealPartiaPublic() *PartialPublic {
	// s_i ^ -1
	s_i_inv := d.suite.G1().Scalar().Inv(d.secret)

	// (s_i ^-1) * x_i * s_i * Q  = x_i * Q
	unprotected := d.suite.G2().Point().Mul(s_i_inv, d.xS)
	// e(P,x_i * Q) = e(P,Q)^x_i = g^x_i
	d.g_x_i = d.suite.GT().PointGT().Pairing(d.suite.G1().Point().Base(), unprotected)
	pp := PartialPublic(share.PubShare{
		I: d.index,
		V: d.g_x_i,
	})
	d.partials = append(d.partials, &share.PubShare{pp.I, pp.V})
	return &pp
}

func (d *DKG) ProcessPartialPublic(p *PartialPublic) {
	if d.index == p.I {
		return
	}
	d.partials = append(d.partials, &share.PubShare{p.I, p.V})
}

func (d *DKG) RecoverPublicKey() kyber.Point {
	fmt.Println("DKG index ", d.index)
	for _, p := range d.partials {
		fmt.Println(p.I, ": ", printHex(p.V))
	}
	public, err := share.RecoverCommit(d.suite.GT(), d.partials, d.t, len(d.participants))
	if err != nil {
		panic(err)
	}
	fmt.Println(printHex(public))
	fmt.Println("-----------------------------")
	d.g_x = public
	return public
}

func (d *DKG) RevealBLSPartial(msg []byte) *PartialBLS {
	// c = H(m)
	c := hashMsg(d.suite, msg)
	// s_i ^ -1
	s_i_inv := d.suite.G1().Scalar().Inv(d.secret)

	left := d.suite.G1().Scalar().Mul(c, s_i_inv)
	sig := d.suite.G1().Point().Mul(left, nil)
	return &PartialBLS{
		Index:     d.index,
		Signature: sig,
		C:         d.xS,
	}
}

func (d *DKG) VerifySignatures(msg []byte, pb []*PartialBLS) error {

	c := hashMsg(d.suite, msg)
	var pubs []*share.PubShare
	for _, p := range pb {
		// e(s, xS)
		paired := d.suite.GT().PointGT().Pairing(p.Signature, p.C)
		// check that the paired signature correspond to g^x_i^c
		// find the g^x_i
		var g_xi kyber.Point
		for _, partial := range d.partials {
			if partial.I != p.Index {
				continue
			}
			g_xi = partial.V
		}
		if g_xi == nil {
			return errors.New("no partial public key found")
		}
		g_xi_c := d.suite.GT().PointGT().Mul(c, g_xi)
		if !g_xi_c.Equal(paired) {
			return errors.New("Partial signature invalid")
		}
		pubs = append(pubs, &share.PubShare{I: p.Index, V: paired})
	}
	signature, err := share.RecoverCommit(d.suite.GT(), pubs, d.t, len(d.participants))
	if err != nil {
		return err
	}
	check := d.suite.GT().Point().Mul(c, d.g_x)
	if !check.Equal(signature) {
		return errors.New("invalid error")
	}
	return nil
}

func hashMsg(s Suite, msg []byte) kyber.Scalar {
	h := sha256.Sum256(msg)
	return s.G1().Scalar().SetBytes(h[:])
}

func printHex(p kyber.Point) string {
	sum := sha256.Sum256([]byte(p.String()))
	return hex.EncodeToString(sum[:])
}
