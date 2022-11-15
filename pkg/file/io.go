package file

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/term"
)

func ReadFileName() string {
	fmt.Print("Enter file name: ")
	reader := bufio.NewReader(os.Stdin)
	fileName, _ := reader.ReadString('\n')
	fileName = fileName[:len(fileName)-1]

	fmt.Println("fileName: ", fileName)
	return fileName
}

func GetPasswordInput() string {
	fmt.Print("Enter password: ")
	password, _ := term.ReadPassword(0)
	fmt.Println()
	return string(password)
}


func SaveSignature(signature []byte) {
	fileName := ReadFileName()
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	file.Write(signature)
}
