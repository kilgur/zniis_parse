package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var alphabet map[rune][]byte

func main() {
	if len(os.Args) != 2 {
		usage()
	}
	phone := os.Args[1]

	alphabet = map[rune][]byte{
		'0': []byte{0x3E, 0x51, 0x49, 0x45, 0x43, 0x3E},
		'1': []byte{0x42, 0x7F, 0x7F, 0x40},
		'2': []byte{0x62, 0x51, 0x49, 0x49, 0x49, 0x46},
		'3': []byte{0x22, 0x41, 0x49, 0x49, 0x49, 0x36},
		'4': []byte{0x8, 0xC, 0xA, 0x9, 0x7F, 0x8},
		'5': []byte{0x27, 0x45, 0x45, 0x45, 0x45, 0x39},
		'6': []byte{0x3E, 0x49, 0x49, 0x49, 0x49, 0x32},
		'7': []byte{0x1, 0x41, 0x21, 0x11, 0x9, 0x7},
		'8': []byte{0x36, 0x49, 0x49, 0x49, 0x49, 0x36},
		'9': []byte{0x6, 0x49, 0x29, 0x19, 0x9, 0x6},
		'a': []byte{0x20, 0x74, 0x54, 0x54, 0x54, 0x54, 0x7C, 0x78, 0x40},
		'b': []byte{0x7F, 0x7F, 0x48, 0x48, 0x48, 0x78, 0x30},
		'c': []byte{0x38, 0x7C, 0x44, 0x44, 0x44, 0x6C, 0x28},
		'd': []byte{0x30, 0x78, 0x48, 0x48, 0x48, 0x7F, 0x7F},
		'e': []byte{0x38, 0x7C, 0x54, 0x54, 0x54, 0x5C, 0x58},
		'f': []byte{0x4, 0x4, 0x7F, 0x7F, 0x5, 0x5},
	}

	// need to disable verify, in othercase got an error
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Get("https://zniis.ru/bdpn/check")
	checkError(err, "cannot get bpdn check page")
	body, err := ioutil.ReadAll(resp.Body)
	checkError(err, "cannot read from bdpn check page")
	resp.Body.Close()

	// searching code block
	rePre := regexp.MustCompile(`<pre[^>]+>([^<]+)</pre>`)
	pre := rePre.FindAllSubmatch(body, -1)
	if len(pre) != 1 {
		fmt.Println("Error. Found more then 1 'pre'.")
		os.Exit(11)
	}

	// searching hidden code
	reR := regexp.MustCompile(`<input type='hidden' name='r' value='(\d+)'>`)
	r := reR.FindAllSubmatch(body, -1)
	if len(r) != 1 {
		fmt.Println("Error. Found more then 1 hidden 'r'.")
		os.Exit(11)
	}
	rcode := string(r[0][1])

	// convert *-image to bytes
	rows := strings.Split(string(pre[0][1]), "\n")
	columns := make([]byte, len(rows[1]))
	symbols := make([][]byte, 0)
	var starts int
	for c := 0; c < len(columns); c++ {
		for r := 1; r < 8; r++ {
			if rows[r][c] == '*' {
				columns[c] |= 1 << uint(r-1)
			}
		}
		if columns[c] == 0 && c > (starts+1) {
			symbols = append(symbols, columns[starts+1:c])
			starts = c
		}
	}
	symbols = append(symbols, columns[starts+1:])

	// trying to parse code with alphabet
	code := try_parse(symbols)
	if strings.Contains(code, "*") {
		fmt.Println("cannot recognize some symbols - %s\nCode from webpage:\n%s\n", code, pre)
		os.Exit(12)
	}

	// getting operator for given number
	resp, err = client.Get(fmt.Sprintf("https://zniis.ru/bdpn/check?num=%s&number=%s&r=%s",
		phone, code, rcode))
	checkError(err, "cannot get result page")
	body, err = ioutil.ReadAll(resp.Body)
	checkError(err, "cannot read result page")
	resp.Body.Close()
	reAnswer := regexp.MustCompile(`Оператор:\s+<b>([^<]+)</b>`)
	found := reAnswer.FindAllSubmatch(body, -1)
	if len(found) != 1 {
		fmt.Println("Error. Found more then one answer.")
		os.Exit(13)
	}
	answer := string(found[0][1])
	fmt.Println(answer)

}

func usage() {
	fmt.Println("USAGE: zniis_parser <phone>")
	fmt.Println("\tphone must be in format 9XXXXXXXXX (10 digits)")
	fmt.Println()
	os.Exit(1)
}

func checkError(err error, msg string) {
	if err != nil {
		fmt.Printf("%s: %s\n", msg, err)
		os.Exit(9)
	}
}

func try_parse(symbols [][]byte) (res string) {
	for _, s := range symbols {
		found := false
		for k, v := range alphabet {
			if len(s) != len(v) {
				continue
			}
			found = true
			for i, b := range s {
				if b != v[i] {
					found = false
					break
				}
			}
			if found {
				res += string(k)
				break
			}
		}
		if !found {
			res += "*"
		}
	}
	return
}
