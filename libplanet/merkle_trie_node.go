package libplanet

import (
	"fmt"

	"github.com/sircoon4/bencodex-go"
)

type node interface {
	name() string
}

type (
	fullNode struct {
		Children [17]node
	}
	shortNode struct {
		Key   []byte
		Value node
	}
	hashNode  []byte // sha256(bencoded)
	valueNode []byte // bencoded
)

func (n *fullNode) name() string {
	return "fullNode"
}
func (n *shortNode) name() string {
	return "shortNode"
}
func (n hashNode) name() string {
	return "hashNode"
}
func (n valueNode) name() string {
	return "valueNode"
}

func (n *fullNode) GetValue() node {
	return n.Children[16]
}
func (n *shortNode) GetValue() node {
	return n.Value
}
func (n hashNode) GetValue() []byte {
	return n
}
func (n valueNode) GetValue() []byte {
	return n
}

func nodeFromData(data any) (node, error) {
	if data == nil {
		return nil, nil
	}

	switch data := data.(type) {
	case []byte:
		return hashNode(data), nil
	case []interface{}:
		list := data
		if len(list) == 2 {
			if list[0] == nil {
				value, err := bencodex.Encode(list[1])
				if err != nil {
					return nil, err
				}
				return valueNode(value), nil
			} else {
				value, err := nodeFromData(list[1])
				if err != nil {
					return nil, err
				}
				return &shortNode{
					Key:   list[0].([]byte),
					Value: value,
				}, nil
			}
		} else if len(list) == 17 {
			children := [17]node{}
			for i, child := range list {
				var err error
				children[i], err = nodeFromData(child)
				if err != nil {
					return nil, err
				}
			}
			return &fullNode{
				Children: children,
			}, nil
		}
	default:
		return nil, fmt.Errorf("invalid node")
	}

	return nil, fmt.Errorf("invalid node")
}
