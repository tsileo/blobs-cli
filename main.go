package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tsileo/blobstash/client/docstore"
)

var noteHeader = []byte("\n# Please write your note. Lines starting with # will be ignored.")

// TempFileName generates a temporary filename
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

type NoteItem struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Kind    string `json:"_kind"`
}

type TodoItem struct {
	Title string `json:"title"`
	Done  bool   `json:"done"`
	Kind  string `json:"_kind"`
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

// FIXME(tsileo) bugfix abbreviation when len(data) == 1

func newAbbrev(data []string) *Abbrev {
	if len(data) == 1 {
		return &Abbrev{
			irefs: map[string]string{
				data[0]: string(data[0][len(data[0])-1]),
			},
			refs: map[string]string{
				string(data[0][len(data[0])-1]): data[0],
			},
		}
	}
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
	// commentLine, _ := regexp.Compile("(?m)^#.+\n")
	// TODO(tsileo) config file with server address and collection name
	col := docstore.New(docstore.DefaultOpts().SetHost(os.Getenv("BLOBS_API_HOST"), os.Getenv("BLOBS_API_KEY"))).Col("blobs-cli-alpha")
	flag.Usage = Usage
	flag.Parse()

	if flag.NArg() < 1 {
		Usage()
		os.Exit(2)
	}

	switch flag.Arg(0) {
	// case "ls":
	// 	items, err := col.Iter(nil)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	ids := []string{}
	// 	// FIXME(tsileo) add Abbrev here, do a first pass before displaying
	// 	for _, item := range items {
	// 		ids = append(ids, Reverse(item["_id"].(string)))
	// 	}
	// 	abbrev := newAbbrev(ids)
	// 	for _, item := range items {
	// 		shortID, _ := abbrev.ShortID(item["_id"].(string))
	// 		fmt.Printf("%v\t%v\t%v\n", shortID, item["_kind"].(string), item["title"])
	// 	}

	case "todo":
		// todos := []*TodoItem{}
		todos := []map[string]interface{}{}
		q := map[string]interface{}{
			"done":  false,
			"_kind": "todo",
		}
		citer, err := col.Iter(q, nil)
		if err != nil {
			panic(err)
		}
		tmp := []map[string]interface{}{}
		for citer.Next(&tmp) {
			todos = append(todos, tmp...)
		}
		if err := citer.Err(); err != nil {
			panic(err)
		}
		// FIXME(tsileo): test the itearator API and see if it looks natural
		ids := []string{}
		// FIXME(tsileo) add Abbrev here, do a first pass before displaying
		for _, todo := range todos {
			ids = append(ids, Reverse(todo["_id"].(string)))
		}
		abbrev := newAbbrev(ids)
		fmt.Sprintf("abbrev:%+v", abbrev)
		if flag.NArg() == 1 {
			for _, todo := range todos {
				shortID, _ := abbrev.ShortID(todo["_id"].(string))
				fmt.Printf("%v\t%v\t%v\n", shortID, todo["title"], todo)
			}
			return
		}
		if flag.Arg(1) == "done" {
			todoArg := flag.Arg(2)
			if todoID, ok := abbrev.ID(todoArg); ok {
				fmt.Printf("will set to ture: %v", todoID)
				if err := col.UpdateID(todoID, map[string]interface{}{
					"$set": map[string]interface{}{
						"done": true,
					},
				}); err != nil {
					panic(err)
				}
				fmt.Printf("Task done")
				return
			}
		}
		// Rebuid the todo item from args
		text := strings.Join(os.Args[2:], " ")
		fmt.Printf("new todo: %v", text)
		// FIXME(ts) make docstore-cli accept struct and convert them to JSOM
		todo := &TodoItem{
			Title: text,
			Done:  false,
			Kind:  "todo",
		}
		js, _ := json.Marshal(todo)
		if err := col.Insert(js, nil); err != nil {
			panic(err)
		}
	// case "note":
	// 	if flag.NArg() >= 1 {
	// 		notes, err := col.Iter(map[string]interface{}{
	// 			"_kind": "note",
	// 		})
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		ids := []string{}
	// 		// FIXME(tsileo) add Abbrev here, do a first pass before displaying
	// 		for _, note := range notes {
	// 			ids = append(ids, Reverse(note["_id"].(string)))
	// 		}
	// 		abbrev := newAbbrev(ids)
	// 		if flag.NArg() == 1 {
	// 			for _, note := range notes {
	// 				shortID, _ := abbrev.ShortID(note["_id"].(string))
	// 				fmt.Printf("%v\t%v\n", shortID, note["title"])
	// 			}
	// 			return
	// 		}
	// 		if flag.Arg(1) == "view" {
	// 			noteArg := flag.Arg(2)
	// 			if noteID, ok := abbrev.ID(noteArg); ok {
	// 				note := map[string]interface{}{}
	// 				if err := col.Get(noteID, &note); err != nil {
	// 					panic(err)
	// 				}
	// 				fmt.Printf("Title: %s\n", note["title"])
	// 				fmt.Printf("%s", note["content"])
	// 				return
	// 			}
	// 			return
	// 		}
	// 	}
	// 	title := strings.Join(os.Args[2:], " ")
	// 	fpath := TempFileName("blobs_note_", "")
	// 	if err := ioutil.WriteFile(fpath, noteHeader, 0644); err != nil {
	// 		panic(fmt.Sprintf("failed to create temp file: %s", err))
	// 	}
	// 	defer os.Remove(fpath)
	// 	cmd := exec.Command("vim", fpath)
	// 	// Hook vim to the current session
	// 	cmd.Stdin = os.Stdin
	// 	cmd.Stdout = os.Stdout
	// 	cmd.Stderr = os.Stderr
	// 	if err := cmd.Start(); err != nil {
	// 		panic(fmt.Sprintf("failed to start vim: %s", err))
	// 	}
	// 	if err := cmd.Wait(); err != nil {
	// 		panic(fmt.Sprintf("failed to edit: %s", err))
	// 	}
	// 	data, err := ioutil.ReadFile(fpath)
	// 	if err != nil {
	// 		panic(fmt.Sprintf("failed to open temp file: %s", err))
	// 	}
	// 	data = commentLine.ReplaceAll(data, []byte(""))
	// 	log.Printf("data=%s", data)
	// 	note := &NoteItem{
	// 		Title:   title,
	// 		Content: string(data),
	// 		Kind:    "note",
	// 	}
	// 	js, _ := json.Marshal(note)
	// 	id, err := col.InsertRaw(js, nil)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Print(id)
	// 	// TODO(tsileo) actually save note
	default:
		Usage()
	}
}
