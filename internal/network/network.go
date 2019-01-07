package network

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	golog "github.com/ipfs/go-log"
	gologging "github.com/whyrusleeping/go-logging"

	"github.com/libp2p/go-libp2p"
	cryptop2p "github.com/libp2p/go-libp2p-crypto"
	"github.com/libp2p/go-libp2p-host"
	netp2p "github.com/libp2p/go-libp2p-net"
	"github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/andskur/simple_chain/internal/blockchain"
)

var mutex = &sync.Mutex{}

// P2pNetwork implements p2p network realisation
type P2pNetwork struct {
	Chain *blockchain.Blockchain
}

// Start P2P Blockchain
func RunP2Pserver(chain *blockchain.Blockchain, listenF int, target string, secio bool, seed int64) {
	net := P2pNetwork{chain}

	// LibP2P code uses golog to log messages. They log with different
	// string IDs (i.e. "swarm"). We can control the verbosity level for
	// all loggers with:
	golog.SetAllLoggers(gologging.INFO)

	if listenF == 0 {
		log.Fatal("Please provide a port to bind on with -l")
	}

	// Make a host that listens on the given multiaddress
	ha, err := net.makeBasicHost(listenF, secio, seed)
	if err != nil {
		log.Fatal(err)
	}

	if target == "" {
		log.Println("listening for connections...")
		// Set a stream handler on host A. /p2p/1.0.0 is
		// a user-defined protocol name.
		ha.SetStreamHandler("/p2p/1.0.0", net.handleStream)

		select {} // hang forever
		/**** This is where the listener code ends ****/
	} else {
		ha.SetStreamHandler("/p2p/1.0.0", net.handleStream)

		// The following code extracts target's peer ID from the
		// given multiaddress
		ipfsaddr, err := ma.NewMultiaddr(target)
		if err != nil {
			log.Fatal(err)
		}

		pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
		if err != nil {
			log.Fatal(err)
		}

		peerid, err := peer.IDB58Decode(pid)
		if err != nil {
			log.Fatal(err)
		}

		// Decapsulate the /ipfs/<peerID> part from the target
		// /ip4/<a.b.c.d>/ipfs/<peer> becomes /ip4/<a.b.c.d>
		targetPeerAddr, _ := ma.NewMultiaddr(
			fmt.Sprintf("/ipfs/%s", peer.IDB58Encode(peerid)))
		targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)

		// We have a peer ID and a targetAddr so we add it to the peerstore
		// so LibP2P knows how to contact it
		ha.Peerstore().AddAddr(peerid, targetAddr, pstore.PermanentAddrTTL)

		log.Println("opening stream")

		// make a new stream from host B to host A
		// it should be handled on host A by the handler we set above because
		// we use the same /p2p/1.0.0 protocol
		s, err := ha.NewStream(context.Background(), peerid, "/p2p/1.0.0")
		if err != nil {
			log.Fatal(err)
		}
		// Create a buffered stream so that read and writes are non blocking.
		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

		// Create a thread to read and write data
		go net.writeData(rw)
		go net.readData(rw)

		select {} // hang forever
	}

}

// makeBasicHost creates a LibP2P host with a random peer ID listening on the
// given multiaddress. It will use secio if secio is true.
func (net *P2pNetwork) makeBasicHost(listenPort int, secio bool, randseed int64) (host.Host, error) {

	// If the seed is zero, use real cryptographic randomness. Otherwise, use a
	// deterministic randomness source to make generated keys stay the same
	// across multiple runs
	var r io.Reader
	if randseed == 0 {
		r = rand.Reader
	} else {
		r = mrand.New(mrand.NewSource(randseed))
	}

	// Generate a key pair for this host. We will use it
	// to obtain a valid host ID.
	priv, _, err := cryptop2p.GenerateKeyPairWithReader(cryptop2p.RSA, 2048, r)
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", listenPort)),
		libp2p.Identity(priv),
	}

	basicHost, err := libp2p.New(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	// Build host multiaddress
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", basicHost.ID().Pretty()))

	// Now we can build a full multiaddress to reach this host
	// by encapsulating both addresses:
	addrs := basicHost.Addrs()
	var addr ma.Multiaddr
	// select the address starting with "ip4"
	for _, i := range addrs {
		if strings.HasPrefix(i.String(), "/ip4") {
			addr = i
			break
		}
	}
	fullAddr := addr.Encapsulate(hostAddr)
	log.Printf("I am %s\n", fullAddr)
	if secio {
		log.Printf("Now run \"go run main.go -l %d -d %s -secio\" on a different terminal\n", listenPort+1, fullAddr)
	} else {
		log.Printf("Now run \"go run main.go -l %d -d %s\" on a different terminal\n", listenPort+1, fullAddr)
	}

	return basicHost, nil
}

func (net *P2pNetwork) handleStream(s netp2p.Stream) {
	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go net.readData(rw)
	go net.writeData(rw)

	// stream 's' will stay open until you close it (or the other side closes it).
}

func (net *P2pNetwork) readData(rw *bufio.ReadWriter) {
	for {
		str, err := rw.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		if str == "" {
			return
		}
		if str != "\n" {

			chain := make([]blockchain.Block, 0)
			if err := json.Unmarshal([]byte(str), &chain); err != nil {
				log.Fatal(err)
			}

			mutex.Lock()
			if len(chain) > len(net.Chain.Blocks) {
				net.Chain.Blocks = chain
				bytes, err := json.MarshalIndent(net.Chain.Blocks, "", " ")
				if err != nil {
					log.Fatal(err)
				}
				// Green console color: 	\x1b[32m
				// Reset console color: 	\x1b[0m
				fmt.Printf("\x1b[32m%s\x1b[0m> ", string(bytes))
			}
			mutex.Unlock()
		}
	}
}

func (net *P2pNetwork) writeData(rw *bufio.ReadWriter) {
	go func() {
		for {
			time.Sleep(5 * time.Second)
			mutex.Lock()
			bytes, err := json.Marshal(net.Chain.Blocks)
			if err != nil {
				log.Println(err)
			}
			mutex.Unlock()

			mutex.Lock()
			_, err = rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
			if err != nil {
				log.Println(err)
			}
			err = rw.Flush()
			if err != nil {
				log.Println(err)
			}
			mutex.Unlock()
		}
	}()

	stdReader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		sendData, err := stdReader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		sendData = strings.Replace(sendData, "\n", "", -1)
		bpm, err := strconv.Atoi(sendData)
		if err != nil {
			log.Fatal(err)
		}
		_, err = net.Chain.AddBlock(bpm)
		if err != nil {
			log.Fatal(err)
		}

		bytes, err := json.Marshal(net.Chain.Blocks)
		if err != nil {
			log.Println(err)
		}

		spew.Dump(net.Chain.Blocks)

		mutex.Lock()
		_, err = rw.WriteString(fmt.Sprintf("%s\n", string(bytes)))
		if err != nil {
			log.Println(err)
		}
		err = rw.Flush()
		if err != nil {
			log.Println(err)
		}
		mutex.Unlock()
	}
}
