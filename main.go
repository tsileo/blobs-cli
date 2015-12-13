package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tsileo/docstore-client"
)

var noteHeader = []byte("\n# Please write your note. Lines starting with # will be ignored.")

// TempFileName generates a temporary filename for use in testing or whatever
func TempFileName(prefix, suffix string) string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), prefix+hex.EncodeToString(randBytes)+suffix)
}

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s SUBCOMMAND\n", os.Args[0])
	flag.PrintDefaults()
}

type TodoItem struct {
	Title string `json:"title"`
	Done  bool   `json:"done"`
}

// Reverse returns its argument string reversed rune-wise left to right.
func Reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

type Abbrev struct {
	refs  map[string]string
	irefs map[string]string
}

func (a *Abbrev) ShortID(id string) (string, bool) {
	short, ok := a.irefs[Reverse(id)]
	return short, ok
}

func (a *Abbrev) ID(short string) (string, bool) {
	id, ok := a.refs[short]
	return Reverse(id), ok
}

func countprefix(data []string, prefix string) (cnt int) {
	for _, word := range data {
		if strings.HasPrefix(word, prefix) {
			cnt++
		}
	}
	return
}

func newAbbrev(data []string) *Abbrev {
	// TODO(tsileo) reverse data here in a new slice
	irefs := map[string]string{}
	refs := map[string]string{}
	for _, word := range data {
		for i, _ := range word {
			prefix := word[:i]
			if prefix == word || countprefix(data, prefix) == 1 {
				refs[prefix] = word
				if _, ok := irefs[word]; !ok {
					irefs[word] = prefix
				}
			}

		}
	}
	return &Abbrev{refs, irefs}
}

func main() {
	// TODO(tsileo) config file with server address and collection name
	col := docstore.New("").Col("blobs-cli-alpha")
	flag.Usage = Usage
	flag.Parse()

	if flag.NArg() < 1 {
		Usage()
		os.Exit(2)
	}

	switch flag.Arg(0) {
	case "todo":
		if flag.NArg() == 1 {
			todos, err := col.Iter(nil)
			if err != nil {
				panic(err)
			}
			ids := []string{}
			// FIXME(tsileo) add Abbrev here, do a first pass before displaying
			for _, todo := range todos {
				ids = append(ids, Reverse(todo["_id"].(string)))
			}
			abbrev := newAbbrev(ids)
			for _, todo := range todos {
				shortID, _ := abbrev.ShortID(todo["_id"].(string))
				fmt.Printf("%v\t%v\n", shortID, todo["title"])
			}
			return
		}
		// Rebuid the todo item from args
		text := strings.Join(os.Args[2:], " ")
		fmt.Printf("new todo: %v", text)
		// FIXME(ts) make docstore-cli accept struct and convert them to JSOM
		todo := &TodoItem{
			Title: text,
			Done:  false,
		}
		js, _ := json.Marshal(todo)
		id, err := col.InsertRaw(js, nil)
		if err != nil {
			panic(err)
		}
		fmt.Print(id)
	case "note":
		fpath := TempFileName("blobs_note_", "")
		if err := ioutil.WriteFile(fpath, noteHeader, 0644); err != nil {
			panic(fmt.Sprintf("failed to create temp file: %s", err))
		}
		defer os.Remove(fpath)
		cmd := exec.Command("vim", fpath)
		// Hook vim to the current session
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			panic(fmt.Sprintf("failed to start vim: %s", err))
		}
		if err := cmd.Wait(); err != nil {
			panic(fmt.Sprintf("failed to edit: %s", err))
		}
		data, err := ioutil.ReadFile(fpath)
		if err != nil {
			panic(fmt.Sprintf("failed to open temp file: %s", err))
		}
		data = bytes.Replace(data, noteHeader, []byte(""), 1)
		log.Printf("data=%s", data)
		// TODO(tsileo) actually save note
	default:
		Usage()
	}
}
