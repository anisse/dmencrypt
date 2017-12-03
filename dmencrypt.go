/*
This prepares a volume for use with aes-cbc-essiv:sha256
*/
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

const (
	keySize    = 32
	saltSize   = 32
	ivSize     = 32
	sectorSize = 512
)

func usage() {
	fmt.Printf(`Usage: %s [opts] password-file input-file output-file
This writes output file in a format that can be loaded with dm-crypt in
aes-cbc-essiv:sha256 mode
Password file is a 32 bytes long binary key.

Options:
`, os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	dec := flag.Bool("d", false, "Decrypt instead of encrypt")
	flag.CommandLine.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) != 3 {
		usage()
	}
	err := dmcrypt(args[0], args[1], args[2], *dec)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}

func dmcrypt(passfile, ifile, ofile string, dec bool) error {
	pass, err := os.Open(passfile)
	if err != nil {
		return errors.Wrap(err, "open password")
	}
	p, err := ioutil.ReadAll(pass)
	if err != nil {
		return errors.Wrap(err, "read password")
	}
	pass.Close()
	if len(p) != keySize {
		return fmt.Errorf("Password file length is %d, expected 32", len(p))
	}

	input, err := os.Open(ifile)
	if err != nil {
		return errors.Wrap(err, "open input")
	}
	defer input.Close()

	output, err := os.Create(ofile)
	if err != nil {
		return errors.Wrap(err, "open output")
	}
	defer output.Close()

	return crypt(input, output, p, dec)
}

func crypt(i io.Reader, o io.Writer, key []byte, dec bool) error {
	in := make([]byte, sectorSize)
	out := make([]byte, sectorSize)
	ivbuf := make([]byte, aes.BlockSize)
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return errors.Wrap(err, "aes not available")
	}
	salt := sha256.Sum256(key)
	aesiv, err := aes.NewCipher(salt[:])
	if err != nil {
		return errors.Wrap(err, "aesiv not available")
	}
	var sector uint64
	for ; ; sector++ {
		n, err := io.ReadAtLeast(i, in, sectorSize)
		if err == io.EOF {
			return nil
		}
		if err == io.ErrUnexpectedEOF {
			return fmt.Errorf("Input isn't a multiple of %d; last %d bytes are ignored", sectorSize, n)
		}
		if err != nil {
			return errors.Wrap(err, "read input")
		}
		//compute IV for this sector
		iv(aesiv, sector, ivbuf)
		//{de,en}crypt this sector
		var enc cipher.BlockMode
		if dec {
			enc = cipher.NewCBCDecrypter(aesblock, ivbuf)
		} else {
			enc = cipher.NewCBCEncrypter(aesblock, ivbuf)
		}
		enc.CryptBlocks(out, in)
		//write encrypted to output
		_, err = o.Write(out)
		if err != nil {
			return errors.Wrap(err, "write output")
		}
	}

}

func iv(ciph cipher.Block, sector uint64, iv []byte) {
	plain := make([]byte, aes.BlockSize)
	iv0 := make([]byte, aes.BlockSize)

	binary.LittleEndian.PutUint64(plain, sector)

	essiv := cipher.NewCBCEncrypter(ciph, iv0)
	essiv.CryptBlocks(iv, plain)
}
