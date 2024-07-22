package libplanet

import (
	"bytes"
	"fmt"
)

func ValidateProof(
	stateRootHash []byte, // []byte
	proof [][]byte, // bencoded list
	key []byte, // []byte
	value []byte, // bencoded
) (bool, error) {
	targetHash := stateRootHash
	nibbles := keybytesToNibbles(key)

	for i, bencodedProofNode := range proof {
		proofNode, err := nodeFromProof(bencodedProofNode)
		if err != nil {
			return false, err
		}

		first := i == 0
		last := i == len(proof)-1

		if _, ok := proofNode.(hashNode); ok {
			return false, fmt.Errorf("proof node cannot be a hash node")
		}

		if err := checkProofNodeHash(targetHash, bencodedProofNode, first); err != nil {
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
