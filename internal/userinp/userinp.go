package userinput

import (
	"errors"
	"fmt"
	"syscall"

	cliarg "github.com/ShuaibKhan786/cipher-project/internal/cmdlineargs"
    esccode "github.com/ShuaibKhan786/cipher-project/internal/escapecode" 

	"golang.org/x/term"
)

func ReadPassword(operation string) ([]byte, error) {
    switch operation {
    case cliarg.EncryptionOp:
		fmt.Print(esccode.Red)
        fmt.Println("WARNING: Please remember your password!",esccode.Reset,esccode.Green)
        fmt.Println("Once the password is lost, decryption will not be possible.")
        fmt.Println("It is highly recommended to use a strong and memorable password.")
        fmt.Println(esccode.Reset)
    case cliarg.DecryptionOp:
    default:
        return nil, errors.New(cliarg.InvalidOpErr)
    }
	fmt.Printf(esccode.Yellow + "Password: " + esccode.Reset)

    pw, err := term.ReadPassword(int(syscall.Stdin))
    if err != nil {
        return nil, err
    }
    fmt.Println()
    return pw, nil
}

func DeleteAllfilesChoice() bool {
    var choice string
    fmt.Println(esccode.Yellow)
    fmt.Println("Do you want to remove all the files? (y/n)",esccode.Reset)
    fmt.Scanf("%s", &choice) 
    switch choice {
    case "y", "Y":
        return true
    case "n", "N":
        return false
    default:
        fmt.Println(esccode.Red,"Invalid choice. Assuming 'no'.",esccode.Reset)
        return false
    }
}

