package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	
	"github.com/golang/protobuf/proto"

	"protobufs"
)

func main() {
	write := flag.Bool("write", false, "write sample output to stdout")
	flag.Parse()

	if *write {
		to_marshal := protobufs.VerifierReveal{
			[]byte{0x01,0x02,0x03,0x04,0x05},
			[]byte{0x09, 0x08, 0x07, 0x06}}

		revelation, err := proto.Marshal(&to_marshal)
		if err == nil {
			os.Stdout.Write(revelation)
		}
	} else {
		data, err := ioutil.ReadAll(os.Stdin)
		var parsed_data protobufs.VerifierReveal
		err = proto.Unmarshal(data, &parsed_data)
		if err != nil {
			fmt.Println("Error:", err.Error())
		} else {
			fmt.Printf("PK: %s\n R: %s\n",
				hex.EncodeToString(parsed_data.PublicKey),
				hex.EncodeToString(parsed_data.RevealValue))
		}
	}
}
