package cmdlineargstest

import (
	"os"
	"reflect"
	"testing"

	"github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
)

func TestCmdlineArgs(t *testing.T) {
	t.Run("testing with enough args",func(t *testing.T) {
		os.Args = []string {
			"processName",
			"operation",
			"file1",
			"file2",
			"file3",
		}

		got := cmdlineargs.NewArgsMetaData()
		want := os.Args

		checkAssertions(got,want,t)
	})

	t.Run("testing with less args",func(t *testing.T) {
		os.Args = []string {
			"processName",
		}

		got := cmdlineargs.NewArgsMetaData()

		if len(got.FileNames) != 0 && len(got.Operation) != 0 {
			t.Errorf("must not get anything")
		} 
	})

	t.Run("testing the file existance and valid operation", func(t *testing.T) {
		os.Args = []string {
			"processName",
			"-e",
			"file1.txt",
		}

		md := cmdlineargs.NewArgsMetaData()
		state,err := md.IsValid()

		if state {
			t.Errorf("must return false")
		}
		if err.Error() != cmdlineargs.InvalidFilenamesErr {
			t.Errorf("must return this error : %v",cmdlineargs.InvalidFilenamesErr)
		}
	})
}

func checkAssertions(got cmdlineargs.ArgsMetaData, want []string,t testing.TB) {
	t.Helper()

	fileNames := want[2:]
	operation := want[1]

	if !reflect.DeepEqual(fileNames,got.FileNames) {
		t.Errorf("got : %v and want %v",got.FileNames,fileNames)
	} 

	if operation != got.Operation {
		t.Errorf("got : %v and want %v",got.FileNames,fileNames)
	}

	if got.NumOfFiles != len(fileNames) {
		t.Errorf("got : %v and want %v",got.NumOfFiles,len(fileNames))
	}
}