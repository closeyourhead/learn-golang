package file

import (
	"os"
	"errors"
)

func IsExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func IsDir(filename string) (bool, error) {
	var err error
	f_stat, err := os.Stat(filename)
	if err != nil {
		return false, errors.New("file not found. filename=" + filename)
	}
	return f_stat.IsDir(), nil
}

func Size(filename string) (int64, error) {
	var err error
	f_stat, err := os.Stat(filename)
	if err != nil {
		return 0, errors.New("file not found. filename=" + filename)
	}
	return f_stat.Size(), nil
}
