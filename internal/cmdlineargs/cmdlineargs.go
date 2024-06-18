package cmdlineargs

import (
	"errors"
	"os"

    esccode "github.com/ShuaibKhan786/cipher-project/internal/escapecode" 
)

const (
	EncryptionOp = "-e"
	DecryptionOp = "-d"
	InvalidOpErr = "invalid operation"
	InvalidFilenamesErr = "one or more filenames doesn't exist"
	InvalidDeExtErr = "invalid file extention \nfiles must end with (.enc) file for decryption"
	InvalidEnExtErr = "invalid file extention \nfiles must not end with (.enc) file for encryption"
	MinimumNumberOfArgs = 3
	EncryptedFileExt = ".enc"
	NoArgs = esccode.Green+"EncryptEase is a file cipher utilizing AES in GCM mode, with key derivation handled by Argon2d." +
	esccode.Blue+"\n\nYou can encrypt or decrypt single or multiple files using a secure password." +
	esccode.Red+"\n\nPlease use a strong and memorable password." +
	esccode.Yellow+"\n\tEncryption: EncryptEase -e your-filenames" +
	"\n\tDecryption: EncryptEase -d your-filenames.enc"+
	esccode.Reset
)

type ArgsMetaData struct {
    FileNames  []string
	NumOfFiles int
    Operation  string
}

func NewArgsMetaData() ArgsMetaData {
    if validateNArgs(MinimumNumberOfArgs) {
        return ArgsMetaData{
            FileNames: extractFilenames(),
            Operation: extractOperation(),
			NumOfFiles: len(extractFilenames()),
        }
    }
    return ArgsMetaData{}
}

func (md *ArgsMetaData) IsValid() (bool,error){
	if md.Operation == "" || md.FileNames == nil {
		return false, errors.New(NoArgs)
	} 
	if !validOperation(md.Operation) {
		return false, errors.New(esccode.Red+InvalidOpErr+esccode.Reset)
	}
	if !validFilenames(md.FileNames) {
		return false, errors.New(esccode.Red+InvalidFilenamesErr+esccode.Reset)
	}

	if ok,op := validExtension(md.FileNames,md.Operation); !ok {
		if op == EncryptionOp {
			return false, errors.New(esccode.Red+InvalidEnExtErr+esccode.Reset)
		}else {
			return false, errors.New(esccode.Red+InvalidDeExtErr+esccode.Reset)
		}
	}

	return true, nil
}

func validOperation(operation string) bool {
	return operation == EncryptionOp || operation == DecryptionOp
}

func validFilenames(filenames []string) bool {
	for _, v := range filenames {
		_, err := os.Stat(v)
		
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func validExtension(filenames []string, op string) (bool,string) {
	for _, v := range filenames {
		extractedExt := extractExt(v) 
		if extractedExt != EncryptedFileExt && op == DecryptionOp {
			return false, op
		}else if extractedExt == EncryptedFileExt && op == EncryptionOp{
			return false, op
		}
	}
	return true, ""
}

func extractExt(filename string) string {
	return filename[len(filename)-len(EncryptedFileExt):]
}

func extractFilenames() []string {
    if validateNArgs(MinimumNumberOfArgs) {
        return os.Args[2:]
    }
    return nil
}

func extractOperation() string {
    if validateNArgs(MinimumNumberOfArgs) {
        return os.Args[1]
    }
    return ""
}

func validateNArgs(n int) bool {
    return len(os.Args) >= n
}
