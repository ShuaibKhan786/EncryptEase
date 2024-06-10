package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
	//setting up signal handler and a notifier 
	sigs := make(chan os.Signal,1)
	notify := make(chan bool,1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Constructor for metadata
	metadata := cliarg.NewArgsMetaData()

	// Validate operation (-e | -d), files
	state, err := metadata.IsValid()
	if !state {
		fmt.Println(input.Red)
		fmt.Println(err, input.Reset)
		fmt.Println()
		os.Exit(0)
	}

	//for tracking progress of ciphe specially for signal
	gtracker := cipher.InitGlobalProgressTracker(metadata.FileNames)

	// Blocking goroutine which blocks until a signal is caught
	go func ()  {
		<- sigs
		notify <- true
		cleanup(gtracker,&metadata)	
	}()

	// Read the user input by echo off
	password, _ := input.ReadPassword(metadata.Operation)

	start := time.Now()
	// Generate a salt and nonce for each files
	pair := salting.NewSaltNoncePair(saltSize, nonceSize, metadata.NumOfFiles)
	pair.GenerateSaltNoncePair(&metadata)

	// Key derivation of key-size 256 bits
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
		displayProgress(metadata.FileNames,channel,notify)
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
				if err := cipher.Encryption(md, channel, gtracker); err != nil {
					fmt.Println(input.Red)
					fmt.Println(err.Error(), input.Reset)
					fmt.Println()
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
				if err := cipher.Decryption(md, channel, gtracker); err != nil {
					fmt.Println(err.Error())
				}
			}(decMetadata)
		}
	}

	workerWg.Wait()
	close(channel)
	progressWg.Wait()
		
	end := time.Now()

	if metadata.Operation == cliarg.EncryptionOp {
		if input.DeleteAllfilesChoice() {
			removesAllfiles(metadata.FileNames)
		}
	}

	elapsed := end.Sub(start)
	fmt.Printf("%v\nIt took %v%v\n", input.White, elapsed, input.Reset)
}


func displayProgress(fileNames []string, channel <-chan cipher.CipherProgress, notify chan bool) {
	filesProgressBuffer := make(map[string]*progressBuffer)
	fmt.Println()
	for _, file := range fileNames {
		filesProgressBuffer[file] = &progressBuffer{filename: file}
		fmt.Println()
	}
	for {
		select {
		case <-notify:
			fmt.Println(input.Reset)
			return 
		case progress, ok := <-channel:
			if !ok {
				fmt.Println(input.Reset)
				return
			}
			if pb, ok := filesProgressBuffer[progress.Filename]; ok {
				pb.percentage = progress.Percentage
			}
			for range filesProgressBuffer {
				fmt.Print(input.MvCrUpClrLine)
			}
			for _, v := range filesProgressBuffer {
				fmt.Printf("%s\t%.15s...\t\t%.0f%%\n", input.Cyan, v.filename, v.percentage)
			}
		}
	}
}




func removesAllfiles(fileNames []string) {
	for _, filename := range fileNames {
		os.Remove(filename)
	}
}	

func cleanup(gtracker *cipher.GlobalProgressTracker,md *cliarg.ArgsMetaData) {
	var ext string
	if md.Operation == cliarg.EncryptionOp {
		ext = cliarg.EncryptedFileExt
	}else {
		ext = ""
	}
	gtracker.Mu.Lock()
	for _, filename := range md.FileNames {
		if gt,ok := gtracker.Tracker[filename]; ok {
			if gt.Tracker {
				os.Remove(filename+ext)
			}
			if gt.Fpair.Rfile != nil {
				gt.Fpair.Rfile.Close()
			}
			if gt.Fpair.Wfile != nil {
				gt.Fpair.Wfile.Close()
			}
		}
	}
	gtracker.Mu.Unlock()
	fmt.Printf("\n%s%s%s\n",input.Red,"Interrupted Sorry",input.Reset)
	os.Exit(1)
}

