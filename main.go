package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/bytom/common"
	"github.com/bytom/consensus"
	"github.com/bytom/crypto"
	"github.com/bytom/crypto/ed25519/chainkd"
	"github.com/bytom/errors"
)

var netParams = &consensus.MainNetParams

func main() {
	if len(os.Args) <= 2 {
		log.Fatal("Please specify the pubkey & suffix.")
	}

	pubkey := os.Args[1]
	suffix := os.Args[2]
	for i := uint64(0); i <= ^uint64(0); i++ {
		for j := uint64(0); j <= ^uint64(0); j++ {
			address, path, err := genAddress(pubkey, i, j)
			if err != nil {
				continue
			}

			if strings.HasSuffix(address, suffix) {
				var pathStr []string
				for _, p := range path {
					pathStr = append(pathStr, hex.EncodeToString(p))
				}

				fmt.Printf("%s: accountIdx %d, addressIdx: %d, path: %v\n", address, i, j, pathStr)
			}
		}
	}
}

func genAddress(pubkey string, accountIdx uint64, addressIdx uint64) (string, [][]byte, error) {
	xPub, err := stringToXPub(pubkey)
	if err != nil {
		return "", nil, errors.Wrap(err, "stringToXPub")
	}

	path := pathForAddress(accountIdx, addressIdx)
	derivedXPub := xPub.Derive(path)
	derivedPK := derivedXPub.PublicKey()
	pubHash := crypto.Ripemd160(derivedPK)

	address, err := common.NewAddressWitnessPubKeyHash(pubHash, netParams)
	if err != nil {
		return "", nil, errors.Wrap(err, "NewAddressWitnessPubKeyHash")
	}

	return address.EncodeAddress(), path, nil
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
