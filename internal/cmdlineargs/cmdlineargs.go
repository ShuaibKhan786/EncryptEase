package cmdlineargs

import (
	"errors"
	"os"
)

const (
	EncryptionOp = "-e"
	DecryptionOp = "-d"
	NoArgsErr = "operation or filenames are not provided"
	InvalidOpErr = "invalid operation"
	InvalidFilenamesErr = "one or more filenames doesn't exist"
	InvalidDeExtErr = "invalid file extention \nfiles must end with (.enc) file for decryption"
	InvalidEnExtErr = "invalid file extention \nfiles must not end with (.enc) file for encryption"
	MinimumNumberOfArgs = 3
	EncryptedFileExt = ".enc"
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
		return false, errors.New(NoArgsErr)
	} 
	if !validOperation(md.Operation) {
		return false, errors.New(InvalidOpErr)
	}
	if !validFilenames(md.FileNames) {
		return false, errors.New(InvalidFilenamesErr)
	}

	if ok,op := validExtension(md.FileNames,md.Operation); !ok {
		if op == EncryptionOp {
			return false, errors.New(InvalidEnExtErr)
		}else {
			return false, errors.New(InvalidDeExtErr)
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
