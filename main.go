package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	_ "encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tsileo/blobstash/pkg/client/docstore"
	"gopkg.in/yaml.v2"
)

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

type FileRef struct {
	Hash string `json:"hash"`
}
type Blob struct {
	CreatedAt int64  `json:"_created,omitempty" yaml:"-"`
	Hash      string `json:"_hash,omitempty" yaml:"-"`
	ID        string `json:"_id,omitempty" yaml:"_id"`
	Type      string `json:"_type" yaml:"-"`
	UpdatedAt int64  `json:"_updated,omitempty" yaml:"-"`
	Archived  bool   `json:"archived" yaml:"archived"`
	Content   string `json:"content" yaml:"-"`
	Title     string `json:"title" yaml:"title"`
}

type Blob2 struct {
	CreatedAt int64  `json:"_created,omitempty" yaml:"-"`
	Hash      string `json:"_hash,omitempty" yaml:"-"`
	ID        string `json:"_id,omitempty" yaml:"_id"`
	Type      string `json:"_type" yaml:"-"`
	UpdatedAt int64  `json:"_updated,omitempty" yaml:"-"`
	Archived  bool   `json:"archived" yaml:"archived"`
	Content   string `json:"content" yaml:"-"`
	Title     string `json:"title" yaml:"title"`
	Ref       string `json:"_ref,omitempty"` // FIXME(tsileo): ref shouldn't be a string in BlobStash response
}

type BlobYAMLHeader struct {
	Archived bool   `yaml:"archived"`
	Title    string `yaml:"title"`
}

type BlobResponse struct {
	Blobs []*Blob `json:"data"`
}

// XXX(tsileo): tabwriter?
func fmtBlob(blob *Blob) {
	updated := blob.CreatedAt
	if blob.UpdatedAt != 0 {
		updated = blob.UpdatedAt
	}
	t := "[N]"
	if blob.Type == "file" {
		t = "[F]"
	}
	fmt.Printf("%s  %s  %s  %s\n", time.Unix(updated, 0).Format("2006-01-02T15:04:05"), blob.ID, t, blob.Title)
}

func toEditor(id string, data []byte) ([]byte, error) {
	// FIXME(tsileo): check if it already exist, and handle the restoration like swp vim
	fpath := filepath.Join(os.TempDir(), fmt.Sprintf("blob_%s", id))
	if err := ioutil.WriteFile(fpath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to create temp file: %s", err)
	}
	defer os.Remove(fpath)
	// Spawn $EDITOR and wait for its exit
	// FIXME(tsileo): use $EDITOR
	cmd := exec.Command("vim", fpath)
	// Hook vim to the current session
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start vim: %s", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("failed to edit: %s", err)
	}
	// Read the file back
	data2, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, fmt.Errorf("failed to open temp file: %s", err)
	}
	return data2, nil
}

func dataToBlob(data []byte) (*Blob, error) {
	parts := bytes.Split(data, []byte("---\n"))
	if len(parts) != 3 {
		return nil, fmt.Errorf("bad input")
	}
	header := &BlobYAMLHeader{}
	if err := yaml.Unmarshal(parts[1], &header); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}
	return &Blob{
		Type:     "note",
		Archived: header.Archived,
		Title:    header.Title,
		Content:  string(parts[2]),
	}, nil

}

type SearchQuery struct {
	Fields      []string `json:"fields"`
	QueryString string   `json:"qs"`
}

func main() {
	// TODO(tsileo) config file with server address and collection name
	opts := docstore.DefaultOpts().SetNamespace("todos").SetHost(os.Getenv("BLOBS_API_HOST"), os.Getenv("BLOBS_API_KEY"))
	opts.SnappyCompression = false // FIXME(tsileo): enable it
	ds := docstore.New(opts)
	col := ds.Col("notes21")
	flag.Usage = Usage
	flag.Parse()

	if flag.NArg() < 1 {
		Usage()
		os.Exit(2)
	}

	switch flag.Arg(0) {
	case "recent", "r":
		iter, err := col.Iter(nil, nil)
		if err != nil {
			panic(err)
		}
		resp := &BlobResponse{}
		iter.Next(resp)
		if err := iter.Err(); err != nil {
			panic(err)
		}
		for _, blob := range resp.Blobs {
			fmtBlob(blob)
		}
	case "search", "s":
		if flag.Arg(1) == "" {
			fmt.Printf("no query")
			return
		}
		iter, err := col.Iter(&docstore.Query{
			StoredQuery: "blobs-search",
			StoredQueryArgs: &SearchQuery{
				Fields:      []string{"title", "content"},
				QueryString: flag.Arg(1),
			},
		}, nil)
		if err != nil {
			panic(err)
		}
		resp := &BlobResponse{}
		iter.Next(resp)
		if err := iter.Err(); err != nil {
			panic(err)
		}
		for _, blob := range resp.Blobs {
			fmtBlob(blob)
		}

	case "edit", "e":
		blob := &Blob2{}
		if err := col.GetID(flag.Arg(1), &blob); err != nil {
			panic(err)
		}
		if blob.Type != "note" {
			panic("not a note")
		}
		out := []byte("---\n")
		d, err := yaml.Marshal(blob)
		if err != nil {
			panic(err)
		}
		out = append(out, d...)
		out = append(out, []byte("---\n")...)
		out = append(out, []byte(blob.Content)...)
		data, err := toEditor(blob.ID, out)
		if err != nil {
			panic(err)
		}
		updatedBlob, err := dataToBlob(data)
		if err != nil {
			panic(err)
		}
		if updatedBlob.Title != blob.Title || updatedBlob.Content != blob.Content {
			if err := col.UpdateID(blob.ID, updatedBlob); err != nil {
				panic(err)
			}
		}
		// fmt.Printf("blob=%+v", updatedBlob)
	case "new", "n":
		out := []byte("---\nupdated: false\ntitle: Untitled\n---\n")
		data, err := toEditor(fmt.Sprintf("%d", time.Now().Unix()), out)
		if err != nil {
			panic(err)
		}
		updatedBlob, err := dataToBlob(data)
		if err != nil {
			panic(err)
		}
		if _, err := col.Insert(updatedBlob, nil); err != nil {
			panic(err)
		}
	case "download", "dl":
		blob := &Blob2{}
		if err := col.GetID(flag.Arg(1), &blob); err != nil {
			panic(err)
		}
		if blob.Type != "file" {
			panic("not a file")
		}
		parts := strings.Split(blob.Ref, ":")
		if err := ds.DownloadAttachment(parts[1], blob.Title); err != nil {
			panic(err)
		}
	case "upload":
	case "convert":
	default:
		Usage()
	}
}
