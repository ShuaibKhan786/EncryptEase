package userinput

import (
	"errors"
	"fmt"
	"syscall"

	cliarg "github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
	"golang.org/x/term"
)

const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
    MvCrUpClrLine = "\033[A\033[2K\r"
)

func ReadPassword(operation string) ([]byte, error) {
    switch operation {
    case cliarg.EncryptionOp:
		fmt.Print(Red)
        fmt.Println("WARNING: Please remember your password!",Reset,Green)
        fmt.Println("Once the password is lost, decryption will not be possible.")
        fmt.Println("It is highly recommended to use a strong and memorable password.")
        fmt.Println(Reset)
    case cliarg.DecryptionOp:
    default:
        return nil, errors.New(cliarg.InvalidOpErr)
    }
	fmt.Printf(Yellow + "Password: " + Reset)

    pw, err := term.ReadPassword(int(syscall.Stdin))
    if err != nil {
        return nil, err
    }
    fmt.Println() 
    return pw, nil
}


