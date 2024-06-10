package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	cipher "github.com/ShuaibKhan786/cipher-project/internal/cipher"
	cliarg "github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
	salting "github.com/ShuaibKhan786/cipher-project/internal/salting"
	input "github.com/ShuaibKhan786/cipher-project/internal/userinp"
	argon "golang.org/x/crypto/argon2"
)

const (
	saltSize  = 16
	nonceSize = 12
	iteration = 1
	memory    = 64 * 1024
	thread    = 4
	keyLength = 32 // i.e. 256 bits
)

type progressBuffer struct {
	filename   string
	percentage float64
}

func main() {
	// Constructor for metadata
	metadata := cliarg.NewArgsMetaData()

	// Validate operation (-e | -d)
	// Validate files
	// If -d then validate the files are encrypted
	state, err := metadata.IsValid()
	if !state {
		fmt.Println(input.Red)
		fmt.Println(err, input.Reset)
		fmt.Println()
		os.Exit(0)
	}

	// Read the user input by echo off
	password, _ := input.ReadPassword(metadata.Operation)

	start := time.Now()
	// Generate a salt
	// If -e then generate new random salt
	// If -d then validate where N-files share the same salt
	// If validates, return the first salt
	// Generating number used once to be used in GCM (modes of cipher)
	pair := salting.NewSaltNoncePair(saltSize, nonceSize, metadata.NumOfFiles)
	pair.GenerateSaltNoncePair(&metadata)

	// Key derivation of key-size 256 bits
	// Argon2 is a key derivation hashing algorithm
	aes256key := argon.IDKey(password, pair.S, iteration, memory, thread, keyLength)

	// using go routine
	// to handle mutiple file cipher process
	var progressWg sync.WaitGroup
	var workerWg sync.WaitGroup
	channel := make(chan cipher.CipherProgress, metadata.NumOfFiles)

	// progress tracker for worker
	progressWg.Add(1)
	go func(progressWg *sync.WaitGroup) {
		defer progressWg.Done()
		filesProgressBuffer := make([]progressBuffer, metadata.NumOfFiles)
		fmt.Println()
		for i, file := range metadata.FileNames {
			filesProgressBuffer[i] = progressBuffer{filename: file}
			fmt.Println()
		}
		for progress := range channel {
			for i := range filesProgressBuffer {
				if progress.Filename == filesProgressBuffer[i].filename {
					filesProgressBuffer[i].percentage = progress.Percentage
				}
			}
			for range filesProgressBuffer {
				fmt.Print(input.MvCrUpClrLine)
			}
			for _, v := range filesProgressBuffer {
				fmt.Printf("%.8s...\t\t%.1f%%\n", v.filename, v.percentage)
			}
		}
	}(&progressWg)

	if metadata.Operation == cliarg.EncryptionOp {
		for index, filename := range metadata.FileNames {
			workerWg.Add(1)
			encMetadata := cipher.EncryptionMetadata{
				Filename: filename,
				Key:      aes256key,
				Nonce:    pair.NN[index],
				Salt:     pair.S,
			}
			go func(md cipher.EncryptionMetadata) {
				defer workerWg.Done()
				if err := cipher.Encryption(md, channel); err != nil {
					fmt.Println(err.Error())
				}
			}(encMetadata)
		}
	} else {
		for index, filename := range metadata.FileNames {
			workerWg.Add(1)
			decMetadata := cipher.DecryptionMetadata{
				Filename: filename,
				Key:      aes256key,
				Nonce:    pair.NN[index],
				SeekSize: int64(len(pair.S) + len(pair.NN[index])),
			}
			go func(md cipher.DecryptionMetadata) {
				defer workerWg.Done()
				if err := cipher.Decryption(md, channel); err != nil {
					fmt.Println(err.Error())
				}
			}(decMetadata)
		}
	}

	workerWg.Wait()
	close(channel)
	progressWg.Wait()

	end := time.Now()
	elapsed := end.Sub(start)
	fmt.Printf("%v\nIt took %v%v\n", input.White, elapsed, input.Reset)
}
