package blockchain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
)

var mutex = &sync.Mutex{}

const difficulty = 1

// Block represent block in blockchain
type Block struct {
	Index      int
	Timestamp  string
	BPM        int
	Hash       string
	PrevHash   string
	Difficulty int
	Nonce      string
}

// BLockchain represent all block in one chain
type Blockchain struct {
	Blocks []Block
}

// create a new block using previous block's hash
func GenerateBlock(oldBlock Block, BPM int) (Block, error) {
	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.BPM = BPM
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Difficulty = difficulty

	for i := 0; ; i++ {
		hexd := fmt.Sprintf("%x", i)
		newBlock.Nonce = hexd
		hash := newBlock.CalculateHash()
		if !IsHashValid(hash, newBlock.Difficulty) {
			fmt.Println(hash, " do more work!")
			time.Sleep(time.Second)
			continue
		} else {
			fmt.Println(hash, " work done!")
			newBlock.Hash = hash
			break
		}
	}

	return newBlock, nil
}

// generate genesis block
func GenerateGenesis() Block {
	t := time.Now()
	genesisBlock := Block{}
	genesisBlock = Block{0, t.String(), 0, genesisBlock.CalculateHash(), "", difficulty, ""}

	return genesisBlock
}

// make sure block is valid by checking index,
// and comparing the hash of the previous block
func (block *Block) IsBlockValid(oldBlock Block) bool {
	if oldBlock.Index+1 != block.Index {
		return false
	}

	if oldBlock.Hash != block.PrevHash {
		return false
	}

	if block.CalculateHash() != block.Hash {
		return false
	}

	return true
}

// calculate Block sha256 hash
func (block *Block) CalculateHash() string {
	record := strconv.Itoa(block.Index) + block.Timestamp + strconv.Itoa(block.BPM) + block.PrevHash + block.Nonce

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)

	return hex.EncodeToString(hashed)
}

// Validate given hash
func IsHashValid(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)

	return strings.HasPrefix(hash, prefix)
}

// start new blockchain with genesis block
func (chain *Blockchain) StartBlockchain() {
	genesisBlock := GenerateGenesis()
	spew.Dump(genesisBlock)

	mutex.Lock()
	chain.Blocks = append(chain.Blocks, genesisBlock)
	mutex.Unlock()
}

// ReplaceChain make sure the chain we're checking
// is longer than the current blockchain
func (chain *Blockchain) ReplaceChain(newBlocks []Block) {
	mutex.Lock()
	if len(newBlocks) > len(chain.Blocks) {
		chain.Blocks = newBlocks
	}
	mutex.Unlock()
}

// AppendBlock generate, validate and append block to current chain
func (chain *Blockchain) AddBlock(BPM int) (newBlock Block, err error) {
	// generate new block
	newBlock, err = GenerateBlock(chain.Blocks[len(chain.Blocks)-1], BPM)
	if err != nil {
		return newBlock, err
	}

	// validate new block
	if newBlock.IsBlockValid(chain.Blocks[len(chain.Blocks)-1]) {
		mutex.Lock()
		chain.Blocks = append(chain.Blocks, newBlock)
		mutex.Unlock()
		return newBlock, nil
	} else {
		return newBlock, errors.New("block does not valid")
	}
}
