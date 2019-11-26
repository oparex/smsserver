package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/tarm/serial"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

var requestCache map[string]int64
var serialPort *serial.Port
var key []byte

func main() {

	logPath := flag.String("logpath", "", "log path")
	listenAddress := flag.String("listen", ":8080", "listen address")
	namePtr := flag.String("name", "", "dev location")
	aesKey := flag.String("key", "", "32 byte aes key")
	flag.Parse()

	if len(*logPath) > 0 {
		f, err := os.OpenFile(*logPath+"smsserver.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		defer f.Close()

		log.SetOutput(f)
	}

	// init serial connection
	if len(*namePtr) > 0 {
		c := &serial.Config{Name: *namePtr, Baud: 9600}
		var err error
		serialPort, err = serial.OpenPort(c)
		if err != nil {
			log.Fatalf("Error opening serial port: %v", err)
		}
	}

	// init key
	if len(*aesKey) > 0 {
		key = []byte(*aesKey)
	}

	requestCache = make(map[string]int64)

	http.HandleFunc("/send", handler)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))

}

func handler(w http.ResponseWriter, r *http.Request) {

	// reject all methods except get
	if r.Method != "GET" {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	// get data parameter
	// return error if not present
	data, ok := r.URL.Query()["data"]
	if !ok || len(data[0]) < 1 {
		log.Print("error parsing url: missing data parameter")
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	// save data to variable
	// set plaintext variable to cipherTest for now
	cipherText := []byte(data[0])
	plainText := cipherText

	// decode if key was provided
	if len(key) > 0 {
		var err error
		plainText, err = decrypt(key, cipherText)
		if err != nil {
			log.Printf("error decrypting cipthertext: %s", err)
			http.Error(w, "404 page not found", http.StatusNotFound)
			return
		}
	}

	params, err := url.ParseQuery(string(plainText))
	if err != nil {
		log.Printf("error parsing plaintext into url parameters: %s", err)
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	validStr, ok := params["valid"]
	if !ok || len(validStr) == 0 {
		log.Printf("missing valid parameter")
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	// get last part of data and convert it to int
	validInt, err := strconv.Atoi(validStr[0])
	if err != nil {
		log.Printf("invalid plaintext: error parsing valid till parameter: %s", err)
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	// check valid parameter
	now := time.Now().Unix()
	if int64(validInt) < now {
		log.Print("invalid plaintext: valid parameter is in the past")
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	// clear all outdated requests
	for k, v := range requestCache {
		if v < now {
			delete(requestCache, k)
		}
	}

	// check request cache for replay attack
	if _, ok := requestCache[string(plainText)]; ok {
		log.Print("invalid plaintext: replay plaintext")
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	// save request to cache
	requestCache[string(plainText)] = int64(validInt)

	sendNumber, ok := params["sendNumber"]
	if !ok {
		log.Printf("missing sendNumber parameter")
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	err = checkSendNumber(sendNumber[0])
	if err != nil {
		log.Printf("wrong sendNumber parameter: %s", err)
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	sendMsg, ok := params["sendMsg"]
	if !ok {
		log.Printf("missing sendMsg parameter")
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	err = checkSendMsg(sendMsg[0])
	if err != nil {
		log.Printf("wrong sendMsg parameter: %s", err)
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	encodedMessage := encodeMessage(sendNumber[0], sendMsg[0])

	// send to serial port
	if serialPort != nil {
		_, err = serialPort.Write(encodedMessage)
		if err != nil {
			log.Printf("error sending data to serial port: %s", err)
			http.Error(w, "404 page not found", http.StatusNotFound)
			return
		}
		log.Printf("Sent message to arduino sms: %s", encodedMessage)
	}

	w.WriteHeader(200)

}

func checkSendNumber(sendNumber string) error {
	return nil
}

func checkSendMsg(sendMsg string) error {
	return nil
}

func encodeMessage(sendNumber, sendMsg string) []byte {
	return []byte(fmt.Sprintf("::%s::%s::\n", sendNumber, sendMsg))
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
