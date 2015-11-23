package json

import (
	"errors"
	"encoding/json"
)

func DecodeJson(b []byte) (map[string]interface{}, error) {
	var data interface{}
	json_err := json.Unmarshal(b, &data)
	if json_err != nil {
		return nil, errors.New("json error: " + json_err.Error());
	}

	return data.(map[string]interface{}), nil
}

func EncodeJson(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}
