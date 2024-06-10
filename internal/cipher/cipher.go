package aescipher

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
	"sync"

	cliarg "github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
	salting "github.com/ShuaibKhan786/cipher-project/internal/salting"
)

type DecryptionMetadata struct {
	Filename string
	Key      []byte
	Nonce    salting.Nonce
	SeekSize int64
}

type EncryptionMetadata struct {
	Filename string
	Key      []byte
	Nonce    salting.Nonce
	Salt     salting.Salt
}

type FilePair struct {
	Rfile *os.File
	Wfile *os.File
}

type CipherProgress struct {
	Filename string
	Percentage float64
}

type MdProgressTracker struct {
	Tracker bool
	Fpair FilePair
}

type GlobalProgressTracker struct {
	Mu sync.Mutex
	Tracker map[string]MdProgressTracker
}

const (
	ChunkSize = 1024 * 1024
)

func InitGlobalProgressTracker(fileNames []string) *GlobalProgressTracker {
	gtracker := &GlobalProgressTracker{
		Tracker: make(map[string]MdProgressTracker),
	}
	
	gtracker.Mu.Lock()
	defer gtracker.Mu.Unlock()
	for _, filename := range fileNames {
		gtracker.Tracker[filename] = MdProgressTracker{Tracker: true}
	}
	return gtracker
}

func Encryption(md EncryptionMetadata,c chan<- CipherProgress,tracker *GlobalProgressTracker) error {
	filepair, err := openCreate(md.Filename, cliarg.EncryptionOp)
	if err != nil {
		return err
	}
	defer func() {
		fileClose(filepair)
		tracker.Mu.Lock()
		tracker.Tracker[md.Filename] = MdProgressTracker{Fpair: FilePair{}}
		tracker.Mu.Unlock()
	}()

	tracker.Mu.Lock()
	tracker.Tracker[md.Filename] = MdProgressTracker{Fpair: filepair}
	tracker.Mu.Unlock()

	filestat, err := filepair.Rfile.Stat()
	if  err != nil{
		fileClose(filepair)
		os.Remove(md.Filename + cliarg.EncryptedFileExt)
		return err
	}
	totalFileSize := float64(filestat.Size())

	if _, err := filepair.Wfile.Write(md.Salt); err != nil {
		fileClose(filepair)
		os.Remove(md.Filename + cliarg.EncryptedFileExt)
		return err
	}
	if _, err := filepair.Wfile.Write(md.Nonce); err != nil {
		fileClose(filepair)
		os.Remove(md.Filename + cliarg.EncryptedFileExt)
		return err
	}

	gcm, err := newgcm(md.Key)
	if err != nil {
		fileClose(filepair)
		os.Remove(md.Filename + cliarg.EncryptedFileExt)
		return err
	}

	rBuffer := bufio.NewReader(filepair.Rfile)
	wBuffer := bufio.NewWriter(filepair.Wfile)
	defer wBuffer.Flush()
	buffer := make([]byte, ChunkSize)

	var currentRead float64
	for {
		n, err := rBuffer.Read(buffer)
		if err != nil && err != io.EOF {
			fileClose(filepair)
			os.Remove(md.Filename + cliarg.EncryptedFileExt)
			return err
		}

		if n == 0 {
			break
		}

		cipherText := gcm.Seal(nil, md.Nonce, buffer[:n], nil)

		if _, err = wBuffer.Write(cipherText); err != nil {
			fileClose(filepair)
			os.Remove(md.Filename + cliarg.EncryptedFileExt)
			return err
		}
		currentRead += float64(n)
		percentage := (currentRead / totalFileSize) * 100.00
		c <- CipherProgress{Filename: md.Filename,Percentage: percentage}
	}
	tracker.Mu.Lock()
	tracker.Tracker[md.Filename] = MdProgressTracker{Tracker: false}
	tracker.Mu.Unlock()
	return nil
}

func Decryption(md DecryptionMetadata,c chan<- CipherProgress, tracker *GlobalProgressTracker) error {
	cachedFilename := md.Filename[:len(md.Filename)-len(cliarg.EncryptedFileExt)]

	filepair, err := openCreate(md.Filename, cliarg.DecryptionOp)
	if err != nil {
		return err
	}
	defer func() {
		fileClose(filepair)
		tracker.Mu.Lock()
		tracker.Tracker[md.Filename] = MdProgressTracker{Fpair: FilePair{}}
		tracker.Mu.Unlock()
	}()

	tracker.Mu.Lock()
	tracker.Tracker[md.Filename] = MdProgressTracker{Fpair: filepair}
	tracker.Mu.Unlock()

	filestat, err := filepair.Rfile.Stat()
	if  err != nil{
		fileClose(filepair)
		os.Remove(cachedFilename)
		return err
	}
	totalFileSize := float64(filestat.Size())

	if _,err = filepair.Rfile.Seek(md.SeekSize,io.SeekStart); err != nil {
		fileClose(filepair)
		os.Remove(cachedFilename)
		return err
	}

	gcm, err := newgcm(md.Key)
	if err != nil {
		fileClose(filepair)
		os.Remove(cachedFilename)
		return err
	}

	rBuffer := bufio.NewReader(filepair.Rfile)
	wBuffer := bufio.NewWriter(filepair.Wfile)
	defer wBuffer.Flush()
	buffer := make([]byte, ChunkSize+gcm.Overhead())

	var currentRead float64
	for {
		n, err := rBuffer.Read(buffer)
		if err != nil && err != io.EOF {
			fileClose(filepair)
			os.Remove(cachedFilename)
			return err
		}

		if n == 0 {
			break
		}
		
		plainText, err := gcm.Open(nil, md.Nonce, buffer[:n], nil)
		if err != nil {
			fileClose(filepair)
			os.Remove(cachedFilename)
			return err
		}

		if _, err = wBuffer.Write(plainText); err != nil {
			fileClose(filepair)
			os.Remove(cachedFilename)
			return err
		}
		currentRead += float64(n)
		percentage := (currentRead / totalFileSize) * 100.00
		c <- CipherProgress{Filename: md.Filename,Percentage: percentage}
	}
	tracker.Mu.Lock()
	tracker.Tracker[md.Filename] = MdProgressTracker{Tracker: false}
	tracker.Mu.Unlock()
	return nil
}

func openCreate(filename, op string) (FilePair, error) {
	Rfile, err := os.Open(filename)
	if err != nil {
		return FilePair{}, err
	}

	var Wfile *os.File
	if op == cliarg.EncryptionOp {
		Wfile, err = os.Create(filename + cliarg.EncryptedFileExt)
	} else {
		Wfile, err = os.Create(filename[:len(filename)-len(cliarg.EncryptedFileExt)])
	}
	if err != nil {
		Rfile.Close()
		return FilePair{}, err
	}

	return FilePair{Rfile: Rfile, Wfile: Wfile}, nil
}

func fileClose(pair FilePair) {
	if pair.Rfile != nil {
		pair.Rfile.Close()
	}
	if pair.Wfile != nil {
		pair.Wfile.Close()
	}
}

func newgcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}
