package cipher_test

import (
	"io"
	"log"
	"os"
	"testing"

	cipher "github.com/ShuaibKhan786/cipher-project/internal/cipher"
	cliarg "github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
	salting "github.com/ShuaibKhan786/cipher-project/internal/salting"
)

func TestCipher(t *testing.T) {
	md := cliarg.ArgsMetaData{
		FileNames: []string{"file1.txt", "file2.txt", "file3.txt"},
		NumOfFiles: 3,
		Operation: "-e",
	}
	gtracker := cipher.InitGlobalProgressTracker(md.FileNames)

	t.Run("testing initialization Progress Tracker", func(t *testing.T) {
		assertFalseNil(t, gtracker)
	})

	t.Run("testing file encryption in a cipher", func(t *testing.T) {
		data := "For testing purpose"

		mdEnc := cipher.EncryptionMetadata{
			Filename: md.FileNames[0],
			Key:      []byte("E4A18C31B5D4923C57A9E4AB96FCA12A"),
			Nonce:    salting.Nonce("6A8B1D4E372A"),
			Salt:     salting.Salt("9DFA18BB1E473CD9"),
		}

		if err := tempOpenWrite(mdEnc.Filename, data); err != nil {
			log.Fatal(err)
		}

		testChannel := make(chan cipher.CipherProgress)
		defer close(testChannel)

		go func() {
			for range testChannel {
				
			}
		}()

		err := cipher.Encryption(mdEnc, testChannel, gtracker)
		assertError(mdEnc.Filename, err, t)

		cipherText, err := tempOpenRead(mdEnc.Filename + cliarg.EncryptedFileExt)
		assertError(mdEnc.Filename, err, t)

		assertEncryption(cipherText, &mdEnc, t)

		os.Remove(mdEnc.Filename)
		os.Remove(mdEnc.Filename + cliarg.EncryptedFileExt)
	})
}

func assertFalseNil(t *testing.T, gtracker *cipher.GlobalProgressTracker) {
	t.Helper()

	gtracker.Mu.Lock()
	defer gtracker.Mu.Unlock()
	for _, filename := range gtracker.Tracker {
		if filename.Tracker {
			t.Errorf("Expecting all filenames to be false")
		}
		if filename.Fpair.Rfile != nil || filename.Fpair.Wfile != nil {
			t.Errorf("Expecting the corresponding file for filename must be nil")
		}
	}
}

func tempOpenWrite(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write([]byte(data)); err != nil {
		return err
	}
	return nil
}

func tempOpenRead(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func assertError(filename string, err error, t *testing.T) {
	t.Helper()
	if err != nil {
		os.Remove(filename)
		t.Errorf("Expected no error, but got an error: %s", err.Error())
	}
}

func assertEncryption(cipherText []byte, want *cipher.EncryptionMetadata, t *testing.T) {
	t.Helper()

	saltLength := len(want.Salt)
	nonceLength := len(want.Nonce)
	if len(cipherText) < saltLength+nonceLength {
		t.Errorf("Cipher text length is too short to extract salt and nonce")
		return
	}

	got := cipher.EncryptionMetadata{
		Filename: want.Filename,
		Key:      want.Key,
		Salt:     salting.Salt(cipherText[:saltLength]),
		Nonce:    salting.Nonce(cipherText[saltLength : saltLength+nonceLength]),
	}

	if !checkEqual(got.Nonce, want.Nonce) {
		t.Errorf("NONCE:\n\tgot : %s\n\twant: %s", got.Nonce, want.Nonce)
	}

	if !checkEqual(got.Salt, want.Salt) {
		t.Errorf("SALT:\n\tgot : %s\n\twant: %s", got.Salt, want.Salt)
	}
}

func checkEqual(got []byte, want []byte) bool {
	for i, v := range want {
		if v != got[i] {
			return false
		}
	}
	return true
}
