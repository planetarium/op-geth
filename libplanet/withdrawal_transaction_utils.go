package libplanet

import (
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

func ParseWithdrawalTransactionInput(input []byte) (map[string]any, error) {
	Uint256, _ := abi.NewType("uint256", "", nil)
	Address, _ := abi.NewType("address", "", nil)

	var arguments = abi.Arguments{
		abi.Argument{Name: "nonce", Type: Uint256, Indexed: false},
		abi.Argument{Name: "from", Type: Address, Indexed: false},
		abi.Argument{Name: "to", Type: Address, Indexed: false},
		abi.Argument{Name: "amount", Type: Uint256, Indexed: false},
	}

	decoded := map[string]any{
		"nonce":  nil, // *big.Int
		"from":   nil, // common.Address
		"to":     nil, // common.Address
		"amount": nil, // *big.Int
	}
	err := arguments.UnpackIntoMap(decoded, input)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func AddressAbi(input [20]byte) []byte {

	Address, _ := abi.NewType("address", "", nil)

	var arguments = abi.Arguments{
		abi.Argument{Name: "address", Type: Address, Indexed: false},
	}

	encoded, err := arguments.Pack(common.BytesToAddress(input[:]))
	if err != nil {
		panic(err)
	}
	return encoded
}
