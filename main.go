package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/bytom/common"
	"github.com/bytom/consensus"
	"github.com/bytom/crypto"
	"github.com/bytom/crypto/ed25519/chainkd"
	"github.com/bytom/errors"
)

var netParams = &consensus.TestNetParams

func main() {
	str, _ := genAddress("c256affcc54cfae619dcbb9494cccce3a605e2f743bf53977891c51efe10764cb62271e0a0247a7253175c2d8799893288a8da5f26ed151ef7a2f0ac15657282", 1, 1)
	fmt.Println(str)
}

func genAddress(pubkey string, accountIdx uint64, addressIdx uint64) (string, error) {
	xPub, err := stringToXPub(pubkey)
	if err != nil {
		return "", errors.Wrap(err, "stringToXPub")
	}

	path := pathForAddress(accountIdx, addressIdx)
	derivedXPub := xPub.Derive(path)
	derivedPK := derivedXPub.PublicKey()
	pubHash := crypto.Ripemd160(derivedPK)

	address, err := common.NewAddressWitnessPubKeyHash(pubHash, netParams)
	if err != nil {
		return "", errors.Wrap(err, "NewAddressWitnessPubKeyHash")
	}

	return address.EncodeAddress(), nil
}

func stringToXPub(xPubStr string) (*chainkd.XPub, error) {
	validStringLen := 128
	if len(xPubStr) != validStringLen {
		return nil, errors.New("bad length of pubkey key string")
	}

	var xPub chainkd.XPub
	_, err := hex.Decode(xPub[:], []byte(xPubStr))
	return &xPub, err
}

func pathForAddress(accountIdx, addressIndex uint64) [][]byte {
	/*
	   path is follow by bip44 https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
	   path[0] and path[1] is bip44 hard code rule
	   path[2] is the account index
	   path[3] is the change index, but it's always 0 in the blockcenter case
	   path[4] is the address index
	*/
	path := [][]byte{
		[]byte{0x2C, 0x00, 0x00, 0x00},
		[]byte{0x99, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00},
		[]byte{0x00, 0x00, 0x00, 0x00},
	}
	binary.LittleEndian.PutUint32(path[2], uint32(accountIdx))
	binary.LittleEndian.PutUint32(path[4], uint32(addressIndex))
	return path
}
