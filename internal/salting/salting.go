package salting

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	cliarg "github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
)

const (
	InvalidPasswordErr = "invalid password"
	FileReadErr        = "error reading file"
)

type Salt []byte
type Nonce []byte
type NNonce []Nonce

type SaltNoncePair struct {
	S  Salt
	NN NNonce
}

func NewSaltNoncePair(saltSize, nonceSize, numOfFiles int) *SaltNoncePair {
	nonces := make(NNonce, numOfFiles)
	for i := range nonces {
		nonces[i] = make(Nonce, nonceSize)
	}
	return &SaltNoncePair{
		S:  make(Salt, saltSize),
		NN: nonces,
	}
}

func (pair *SaltNoncePair) GenerateSaltNoncePair(md *cliarg.ArgsMetaData) error {
	if md.Operation == cliarg.EncryptionOp {
		return generateRandomSaltNoncePair(pair)
	}else {
		return extractSaltNoncePair(md,pair)
	}
}

func generateRandomSaltNoncePair(pair *SaltNoncePair) error {
	if _,err := rand.Read(pair.S); err != nil {
		return err
	}

	for i := 0 ; i < len(pair.NN) ; i++ {
		if _,err := rand.Read(pair.NN[i]); err != nil {
			return err
		}
	}
	return nil
}

func extractSaltNoncePair(md *cliarg.ArgsMetaData, pair *SaltNoncePair) error {
	extractedSaltSize := len(pair.S)
	salt1 := make(Salt, extractedSaltSize)
	salt2 := make(Salt, extractedSaltSize)
	for i, v := range md.FileNames {
		if i == 0 {
			if err := extractSaltNonce(&salt1, &pair.NN[i], v); err != nil {
				return err
			}
			if len(md.FileNames) == 1 {
				break
			}
		} else {
			fmt.Println(v)
			if err := extractSaltNonce(&salt2, &pair.NN[i], v); err != nil {
				return err
			}
			if !compareSalt(&salt1, &salt2) {
				return errors.New(InvalidPasswordErr)
			}
		}
	}
	copy(pair.S, salt1)
	return nil
}

func extractSaltNonce(s *Salt, n *Nonce, filename string) error {
	buffer := make([]byte,len(*s)+len(*n))
	file, err := os.Open(filename)
	if err != nil {
		return errors.New(FileReadErr)
	}
	defer file.Close()

	_, err = file.Read(buffer)
	if err != nil {
		return errors.New(FileReadErr)
	}
	copy(*s,buffer[:len(*s)])
	copy(*n,buffer[len(*s):])
	return nil
}

func compareSalt(salt1, salt2 *Salt) bool {
	for i, v := range *salt1 {
		if v != (*salt2)[i] {
			return false
		}
	}
	return true
}
