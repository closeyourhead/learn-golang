package strings

import (
	"errors"
	"io/ioutil"
	"strings"
	"bytes"
	"encoding/base64"
)

func String2Bytes(str string) ([]byte, error) {
	r := strings.NewReader(str)
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.New("string read error" + err.Error());
	}
	return b, nil
}

func Bytes2String(byte_arg []byte) string {
	return bytes.NewBuffer(byte_arg).String()
}
