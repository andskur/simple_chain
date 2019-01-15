package http

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"github.com/andskur/simple_chain/internal/blockchain"
)

// Message takes incoming JSON payload for writing heart rate
type Message struct {
	BPM int
}

// Handlers depends with one blockchain
type Handlers struct {
	Chain *blockchain.Blockchain
}

// Webserver implementation
func RunHttpServer(chain *blockchain.Blockchain) {
	fmt.Println("Starting http server")
	mux := MakeMuxRouter(chain)
	httpAddr := os.Getenv("PORT")
	log.Println("Listening on ", os.Getenv("PORT"))

	s := &http.Server{
		Addr:           ":" + httpAddr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.ListenAndServe()
}

// Create Handler
func MakeMuxRouter(chain *blockchain.Blockchain) http.Handler {
	handlers := Handlers{chain}
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/", handlers.HandleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handlers.HandleWriteBLock).Methods("POST")

	return muxRouter
}

// get all blocks in blockchain
func (srv *Handlers) HandleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(srv.Chain.Blocks, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	io.WriteString(w, string(bytes))
}

// write blockchain when we receive an http request
func (srv *Handlers) HandleWriteBLock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var m Message

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&m); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()

	newBlock, err := srv.Chain.AddBlock(m.BPM)
	if err != nil {
		respondWithJSON(w, r, http.StatusInternalServerError, m)
		return
	}

	respondWithJSON(w, r, http.StatusCreated, newBlock)
}

// takes JSON payload as an input for heart rate (BPM)
func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.WriteHeader(code)
	w.Write(response)
}
