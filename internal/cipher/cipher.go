package aescipher

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"

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
	rfile *os.File
	wfile *os.File
}

type CipherProgress struct {
	Filename string
	Percentage float64
}

const (
	ChunkSize = 1024 * 1024
)

func Encryption(md EncryptionMetadata,c chan<- CipherProgress) error {
	filepair, err := openCreate(md.Filename, cliarg.EncryptionOp)
	if err != nil {
		return err
	}
	defer fileClose(filepair)

	filestat, err := filepair.rfile.Stat()
	if  err != nil{
		fileClose(filepair)
		os.Remove(md.Filename + cliarg.EncryptedFileExt)
		return err
	}
	totalFileSize := float64(filestat.Size())

	if _, err := filepair.wfile.Write(md.Salt); err != nil {
		fileClose(filepair)
		os.Remove(md.Filename + cliarg.EncryptedFileExt)
		return err
	}
	if _, err := filepair.wfile.Write(md.Nonce); err != nil {
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

	rBuffer := bufio.NewReader(filepair.rfile)
	wBuffer := bufio.NewWriter(filepair.wfile)
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
	return nil
}

func Decryption(md DecryptionMetadata,c chan<- CipherProgress) error {
	cachedFilename := md.Filename[:len(md.Filename)-len(cliarg.EncryptedFileExt)]

	filepair, err := openCreate(md.Filename, cliarg.DecryptionOp)
	if err != nil {
		return err
	}
	defer fileClose(filepair)

	filestat, err := filepair.rfile.Stat()
	if  err != nil{
		fileClose(filepair)
		os.Remove(cachedFilename)
		return err
	}
	totalFileSize := float64(filestat.Size())

	if _,err = filepair.rfile.Seek(md.SeekSize,io.SeekStart); err != nil {
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

	rBuffer := bufio.NewReader(filepair.rfile)
	wBuffer := bufio.NewWriter(filepair.wfile)
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
	return nil
}

func openCreate(filename, op string) (FilePair, error) {
	rfile, err := os.Open(filename)
	if err != nil {
		return FilePair{}, err
	}

	var wfile *os.File
	if op == cliarg.EncryptionOp {
		wfile, err = os.Create(filename + cliarg.EncryptedFileExt)
	} else {
		wfile, err = os.Create(filename[:len(filename)-len(cliarg.EncryptedFileExt)])
	}
	if err != nil {
		rfile.Close()
		return FilePair{}, err
	}

	return FilePair{rfile: rfile, wfile: wfile}, nil
}

func fileClose(pair FilePair) {
	if pair.rfile != nil {
		pair.rfile.Close()
	}
	if pair.wfile != nil {
		pair.wfile.Close()
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
