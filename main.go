package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tsileo/docstore-client"
)

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s SUBCOMMAND\n", os.Args[0])
	flag.PrintDefaults()
}

type TodoItem struct {
	Tittle string `json:"title"`
}

type Abbrev struct {
	refs  map[string]string
	irefs map[string]string
}

func (a *Abbrev) ShortID(id string) (string, bool) {
	short, ok := a.irefs[id]
	return short, ok
}

func (a *Abbrev) ID(short string) (string, bool) {
	id, ok := a.refs[short]
	return id, ok
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
			// FIXME(tsileo) add Abbrev here, do a first pass before displaying
			for _, todo := range todos {
				fmt.Printf("%v\n", todo["title"])
			}
			return
		}
		// Rebuid the todo item from args
		text := strings.Join(os.Args[2:], " ")
		fmt.Printf("new todo: %v", text)
		// FIXME(ts) make docstore-cli accept struct and convert them to JSOM
		todo := &TodoItem{text}
		js, _ := json.Marshal(todo)
		id, err := col.InsertRaw(js, nil)
		if err != nil {
			panic(err)
		}
		fmt.Print(id)
	default:
		Usage()
	}
}
