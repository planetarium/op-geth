// This code is adapted from the following repository:
// Repository: https://github.com/stackup-wallet/erc-4337-execution-clients
// Original file: tracers/bundler_executor_next.go.template

package native

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/eth/tracers/internal"
)

func init() {
	tracers.DefaultDirectory.Register("bundlerExecutorTracer", newBundlerExecutor, false)
}

type userOperationEvent struct {
	Data   hexutil.Bytes   `json:"data"`
	Topics []hexutil.Bytes `json:"topics"`
}

type bundlerExecutorResults struct {
	Reverts            []hexutil.Bytes     `json:"reverts"`
	ValidationOOG      bool                `json:"validationOOG"`
	ExecutionOOG       bool                `json:"executionOOG"`
	ExecutionGasLimit  uint64              `json:"executionGasLimit"`
	UserOperationEvent *userOperationEvent `json:"userOperationEvent,omitempty"`
	Output             hexutil.Bytes       `json:"output"`
	Error              string              `json:"error"`
}

type gasStackItem struct {
	used     uint64
	required uint64
}

type bundlerExecutor struct {
	vm *tracing.VMContext

	Reverts            []hexutil.Bytes
	ValidationOOG      bool
	ExecutionOOG       bool
	ExecutionGasLimit  uint64
	UserOperationEvent *userOperationEvent
	Output             hexutil.Bytes
	Error              string

	depth                     int
	executionGasStack         map[int]*gasStackItem
	marker                    int
	validationMarker          int
	executionMarker           int
	userOperationEventTopics0 string
}

func newBundlerExecutor(ctx *tracers.Context, cfg json.RawMessage) (*tracers.Tracer, error) {
	userOperationEventTopics0 := "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"

	t := &bundlerExecutor{
		Reverts:            []hexutil.Bytes{},
		ValidationOOG:      false,
		ExecutionOOG:       false,
		ExecutionGasLimit:  0,
		UserOperationEvent: nil,
		Output:             []byte{},
		Error:              "",

		depth:                     0,
		executionGasStack:         map[int]*gasStackItem{},
		marker:                    0,
		validationMarker:          1,
		executionMarker:           3,
		userOperationEventTopics0: userOperationEventTopics0,
	}

	return &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: t.OnTxStart,
			OnEnter:   t.OnEnter,
			OnExit:    t.OnExit,
			OnOpcode:  t.OnOpcode,
		},
		GetResult: t.GetResult,
	}, nil
}

func (b *bundlerExecutor) isValidation() bool {
	return b.marker >= b.validationMarker && b.marker < b.executionMarker
}

func (b *bundlerExecutor) isExecution() bool {
	return b.marker == b.executionMarker
}

func (b *bundlerExecutor) isUserOperationEvent(scope tracing.OpContext) bool {
	stackSize := len(scope.StackData())
	stackLast := stackSize - 1
	return scope.StackData()[stackLast-2].Hex() == b.userOperationEventTopics0
}

func (b *bundlerExecutor) setUserOperationEvent(opcode string, scope tracing.OpContext) {
	stackSize := len(scope.StackData())

	stackLast := stackSize - 1
	count, _ := strconv.Atoi(opcode[3:])
	ofs := scope.StackData()[stackLast].ToBig().Int64()
	len := scope.StackData()[stackLast-1].ToBig().Int64()
	topics := []hexutil.Bytes{}
	for i := 0; i < count; i++ {
		topics = append(topics, scope.StackData()[stackLast-(2+i)].Bytes())
	}

	m, _ := internal.GetMemoryCopyPadded(scope.MemoryData(), ofs, len)
	b.UserOperationEvent = &userOperationEvent{
		Data:   m,
		Topics: topics,
	}
}

func (b *bundlerExecutor) captureEnd(output []byte, err error) {
	b.Output = output
	if err != nil {
		b.Error = err.Error()
	}
}

func (b *bundlerExecutor) OnTxStart(
	vm *tracing.VMContext,
	tx *types.Transaction,
	from common.Address,
) {
	b.vm = vm
}

func (b *bundlerExecutor) GetResult() (json.RawMessage, error) {
	ber := bundlerExecutorResults{
		Reverts:            b.Reverts,
		ValidationOOG:      b.ValidationOOG,
		ExecutionOOG:       b.ExecutionOOG,
		ExecutionGasLimit:  b.ExecutionGasLimit,
		UserOperationEvent: b.UserOperationEvent,
		Output:             b.Output,
		Error:              b.Error,
	}

	r, err := json.Marshal(ber)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (b *bundlerExecutor) OnEnter(
	depth int,
	typ byte,
	from common.Address,
	to common.Address,
	input []byte,
	gas uint64,
	value *big.Int,
) {
	if b.isExecution() {
		next := b.depth + 1
		if _, ok := b.executionGasStack[next]; !ok {
			b.executionGasStack[next] = &gasStackItem{used: 0, required: 0}
		}
	}
}

func (b *bundlerExecutor) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if depth == 0 {
		b.captureEnd(output, err)
		return
	}

	if b.isExecution() {
		if err != nil {
			b.Reverts = append(b.Reverts, output)
		}

		if b.depth >= 2 {
			// Get the final gas item for the nested frame.
			nd := b.depth + 1
			if _, ok := b.executionGasStack[nd]; !ok {
				b.executionGasStack[nd] = &gasStackItem{used: 0, required: 0}
			}
			nested := b.executionGasStack[nd]

			// Reset the nested gas item to prevent double counting on re-entry.
			b.executionGasStack[nd] = &gasStackItem{used: 0, required: 0}

			// Keep track of the total gas used by all frames at this depth.
			// This does not account for the gas required due to the 63/64 rule.
			b.executionGasStack[b.depth].used += gasUsed

			// Keep track of the total gas required by all frames at this depth.
			// This accounts for additional gas needed due to the 63/64 rule.
			b.executionGasStack[b.depth].required +=
				gasUsed - nested.used + uint64(math.Ceil(float64(nested.required)*64/63))

			// Keep track of the final gas limit.
			b.ExecutionGasLimit = b.executionGasStack[b.depth].required
		}
	}
}

func (b *bundlerExecutor) OnOpcode(
	pc uint64,
	op byte,
	gas, cost uint64,
	scope tracing.OpContext,
	rData []byte,
	depth int,
	err error,
) {
	opcode := vm.OpCode(op).String()
	b.depth = depth
	if b.depth == 1 && opcode == "NUMBER" {
		b.marker++
	}

	if b.depth <= 2 && strings.HasPrefix(opcode, "LOG") && b.isUserOperationEvent(scope) {
		b.setUserOperationEvent(opcode, scope)
	}

	if gas < cost && b.isValidation() {
		b.ValidationOOG = true
	}

	if gas < cost && b.isExecution() {
		b.ExecutionOOG = true
	}
}
