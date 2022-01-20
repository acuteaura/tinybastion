package main

import "github.com/acuteaura/tinybastion"

func main() {
	_, err := tinybastion.New(tinybastion.Config{DeviceName: "tinybastion"})
	if err != nil {
		panic(err)
	}
}
