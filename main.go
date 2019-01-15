package main

import (
	"flag"
	"log"

	"github.com/joho/godotenv"

	httpserver "github.com/andskur/simple_chain/http"
	"github.com/andskur/simple_chain/internal/blockchain"
	"github.com/andskur/simple_chain/internal/network"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	Chain := &blockchain.Blockchain{}

	listenF := flag.Int("l", 0, "wait for incoming conections")
	target := flag.String("d", "", "target peer to dial")
	secio := flag.Bool("secio", false, "enable secio")
	seed := flag.Int64("seed", 0, "set random seed for id generation")
	startHttp := flag.Bool("http", false, "start http server")
	flag.Parse()

	if *startHttp {
		go httpserver.RunHttpServer(Chain)
	}

	err = network.RunP2Pserver(Chain, *listenF, *target, *secio, *seed)
	if err != nil {
		log.Fatal(err)
	}
}
