package saltingtest

import (
	"os"
	"reflect"
	"testing"

	cliarg "github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
	salting "github.com/ShuaibKhan786/cipher-project/internal/salting"
)

func TestSalting(t *testing.T) {
	md := cliarg.NewArgsMetaData()
	md.Operation = cliarg.EncryptionOp
	md.FileNames = []string {"test1.salt","test2.salt","test3.salt"}
	md.NumOfFiles = 3

	pair := salting.NewSaltNoncePair(16,12,md.NumOfFiles)

	err := pair.GenerateSaltNoncePair(&md)

	t.Run("testing salt generation for encryption operation",func(t *testing.T) {

		assertError(t,err)

		if len(pair.S) != 16 {
			t.Errorf("got : %v want : %v",len(pair.S),16)
		}
		if len(pair.NN) != md.NumOfFiles {
			t.Errorf("got : %v want : %v",len(pair.NN),md.NumOfFiles)
		}
		for _, v := range pair.NN {
			if len(v) != 12 {
				t.Errorf("got : %v want : %v",len(v),12)
			}
		}
	})

	t.Run("testing salt verification for decryption operation", func(t *testing.T) {
		err := testFakeFile(&md,pair)
		if err != nil {
			t.Errorf(err.Error())
		}

		defer testFakeFileRem(md.FileNames)

		mdDe := cliarg.NewArgsMetaData()
		mdDe.Operation = cliarg.DecryptionOp
		mdDe.FileNames = md.FileNames
		mdDe.NumOfFiles = md.NumOfFiles

		pairDe := salting.NewSaltNoncePair(16,12,mdDe.NumOfFiles)

		err = pairDe.GenerateSaltNoncePair(&mdDe)

		assertError(t,err)

		if !reflect.DeepEqual(pair,pairDe) {
			t.Errorf("got : %x and want %x",pairDe,pair)
		}
	})
}

func testFakeFile(md *cliarg.ArgsMetaData,pair *salting.SaltNoncePair) error {
	for i, v := range md.FileNames {
		file, err := os.Create(v)
		if err != nil {
			file.Close()
			testFakeFileRem(md.FileNames[:i])
			return err
		}
		file.Write(pair.S)
		file.Write(pair.NN[i])
		file.Close()
	}
	return nil
}

func testFakeFileRem(fileNames []string) {
	for _, v := range fileNames {
		os.Remove(v)
	}
}

func assertError(t *testing.T,err error) {
	t.Helper()
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}
}
