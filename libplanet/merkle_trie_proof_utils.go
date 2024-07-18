package libplanet

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

func ParseMerkleTrieProofInput(input []byte) (map[string]any, error) {
	Bytes, _ := abi.NewType("bytes", "", nil)
	BytesArr, _ := abi.NewType("bytes[]", "", nil)

	var arguments = abi.Arguments{
		abi.Argument{Name: "stateRootHash", Type: Bytes, Indexed: false},
		abi.Argument{Name: "proof", Type: BytesArr, Indexed: false},
		abi.Argument{Name: "key", Type: Bytes, Indexed: false},
		abi.Argument{Name: "value", Type: Bytes, Indexed: false},
	}

	decoded := map[string]any{
		"stateRootHash": nil,
		"proof":         nil,
		"key":           nil,
		"value":         nil,
	}
	err := arguments.UnpackIntoMap(decoded, input)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func BoolAbi(input bool) []byte {

	Bool, _ := abi.NewType("bool", "", nil)

	var arguments = abi.Arguments{
		abi.Argument{Name: "proofResult", Type: Bool, Indexed: false},
	}

	encoded, err := arguments.Pack(input)
	if err != nil {
		panic(err)
	}
	return encoded
}

func keybytesToNibbles(str []byte) []byte {
	l := len(str) * 2
	var nibbles = make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	return nibbles
}

func checkProofNodeHash(
	targetHash []byte, // sha256(bencoded)
	bencodedProofNode []byte, // bencoded
	first bool,
) error {
	if !first && len(bencodedProofNode) <= sha256.Size {
		return fmt.Errorf("proof node must be longer than hash size")
	}

	proofNodeHash := sha256.Sum256(bencodedProofNode)
	if !bytes.Equal(proofNodeHash[:], targetHash) {
		return fmt.Errorf("proof node hash does not match target hash")
	}

	return nil
}

func resolveToNextCandidateNode(
	proofNode node,
	nibbles []byte,
) (node, []byte, error) {
	switch proofNode := proofNode.(type) {
	case hashNode:
		hash := proofNode
		return hash, nibbles, nil
	case valueNode:
		value := proofNode
		return value, nibbles, nil
	case *shortNode:
		short := proofNode
		if len(nibbles) < len(short.Key) {
			return nil, nil, fmt.Errorf("nibbles exhausted")
		}

		if bytes.Equal(short.Key, nibbles[:len(short.Key)]) {
			return resolveToNextCandidateNode(short.Value, nibbles[len(short.Key):])
		} else {
			return nil, nil, fmt.Errorf("key mismatch")
		}
	case *fullNode:
		full := proofNode
		if len(nibbles) == 0 {
			if full.GetValue() != nil {
				return full.GetValue(), nil, nil
			} else {
				return nil, nil, fmt.Errorf("nibbles exhausted")
			}
		}
		child := full.Children[int(nibbles[0])]
		if child == nil {
			return nil, nil, fmt.Errorf("child not found")
		}
		return resolveToNextCandidateNode(child, nibbles[1:])
	}

	return nil, nil, fmt.Errorf("invalid proof node")
}
