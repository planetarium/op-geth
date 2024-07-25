package libplanet

import (
	"bytes"
	"fmt"

	"github.com/sircoon4/bencodex-go"
)

func ValidateProof(
	stateRootHash []byte, // sha256(bencoded)
	proof []byte, // bencoded(list)
	key []byte, // []byte
	value []byte, // bencoded
) (bool, error) {
	targetHash := stateRootHash
	nibbles := keybytesToNibbles(key)
	decodedProofList, err := bencodex.Decode(proof)
	if err != nil {
		return false, err
	}
	proofList, ok := decodedProofList.([]any)
	if !ok {
		return false, fmt.Errorf("proof must be a list")
	}

	for i, proofData := range proofList {
		proofNode, err := nodeFromData(proofData)
		if err != nil {
			return false, err
		}

		first := i == 0
		last := i == len(proofList)-1

		if _, ok := proofNode.(hashNode); ok {
			return false, fmt.Errorf("proof node cannot be a hash node")
		}

		if err := checkProofNodeHash(targetHash, proofData, first); err != nil {
			return false, err
		}

		nextNode, nextNibbles, err := resolveToNextCandidateNode(proofNode, nibbles)
		if err != nil {
			return false, err
		}

		switch nextNode := nextNode.(type) {
		case hashNode:
			if !last {
				nibbles = nextNibbles
				targetHash = nextNode.GetValue()
				continue
			} else {
				return false, fmt.Errorf("hash node cannot be the last node")
			}
		case valueNode:
			if last {
				if len(nextNibbles) != 0 {
					return false, fmt.Errorf("nibbles not exhausted")
				}

				if bytes.Equal(nextNode.GetValue(), value) {
					return true, nil
				} else {
					return false, fmt.Errorf("value mismatch")
				}
			} else {
				return false, fmt.Errorf("value node must be the last node")
			}
		default:
			return false, fmt.Errorf("invalid node")
		}
	}

	return false, fmt.Errorf("proof exhausted")
}
