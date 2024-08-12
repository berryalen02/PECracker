package main

import (
	"crypto/rand"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

// ExtractPEHeader extracts the PE header from a given file
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

// WritePEHeader writes the PE header to a binary file
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

// ReplacePEHeader replaces the PE header of a target file with a given header
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

// RandomizeByteAtOffset randomizes a byte at a specific offset in the file
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

func main() {
	extract := flag.String("extract", "", "从PE文件提取文件头")
	output := flag.String("output", "header.bin", "输出提取的文件头的路径")
	importHeader := flag.String("import", "", "导入提取好的文件头")
	target := flag.String("target", "", "需要替换文件头的目标PE文件")

	flag.Parse()

	if *extract != "" {
		header, err := ExtractPEHeader(*extract)
		if err != nil {
			fmt.Println("Error extracting PE header:", err)
			return
		}

		err = WritePEHeader(header, *output)
		if err != nil {
			fmt.Println("Error writing PE header to file:", err)
			return
		}

		fmt.Println("PE header extracted and written to", *output)
	} else if *importHeader != "" && *target != "" {
		header, err := os.ReadFile(*importHeader)
		if err != nil {
			fmt.Println("Error reading PE header from file:", err)
			return
		}

		err = ReplacePEHeader(*target, header)
		if err != nil {
			fmt.Println("Error replacing PE header:", err)
			return
		}

		// Randomize a byte at offset 0x23 to change the hash
		err = RandomizeByteAtOffset(*target, 0x23)
		if err != nil {
			fmt.Println("Error randomizing byte at offset 0x23:", err)
			return
		}

		fmt.Println("PE header replaced and byte at offset 0x23 randomized in", *target)
	} else {
		fmt.Println("Usage:")
		fmt.Println("  -extract <file> -output <file> : Extract PE header from file and save to output file")
		fmt.Println("  -import <file> -target <file>  : Import PE header from file and replace target file's header")
	}
}
