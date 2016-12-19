package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/tsileo/blobstash/pkg/client/docstore"
	"gopkg.in/yaml.v2"
)

var cache string

var errCacheFileExist = errors.New("cache file already exist")

func printErr(msg string, err error) {
	fmt.Printf("%s: %v", msg, err)
	os.Exit(1)
}

func cacheDir() (string, error) {
	// Get the home directory
	d, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	// The cache dir will be stored at `~/var/blobs-cli`
	p := filepath.Join(d, "var", "blobs-cli")

	// Create the directory if needed
	if _, err := os.Stat(p); os.IsNotExist(err) {
		if err := os.MkdirAll(p, 0700); err != nil {
			return "", err
		}
	}

	return p, nil
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
	CreatedAt int64                  `json:"_created,omitempty" yaml:"-"`
	Hash      string                 `json:"_hash,omitempty" yaml:"-"`
	ID        string                 `json:"_id,omitempty" yaml:"_id"`
	Type      string                 `json:"_type" yaml:"-"`
	UpdatedAt int64                  `json:"_updated,omitempty" yaml:"-"`
	Archived  bool                   `json:"archived" yaml:"archived"`
	Content   string                 `json:"content" yaml:"-"`
	Title     string                 `json:"title" yaml:"title"`
	Meta      map[string]interface{} `json:"meta,omitempty" yaml:"meta,omitempty"`
}

type Blob2 struct {
	CreatedAt int64                  `json:"_created,omitempty" yaml:"-"`
	Hash      string                 `json:"_hash,omitempty" yaml:"-"`
	ID        string                 `json:"_id,omitempty" yaml:"_id"`
	Type      string                 `json:"_type" yaml:"-"`
	UpdatedAt int64                  `json:"_updated,omitempty" yaml:"-"`
	Archived  bool                   `json:"archived" yaml:"archived"`
	Content   string                 `json:"content" yaml:"-"`
	Title     string                 `json:"title" yaml:"title"`
	Ref       string                 `json:"_ref,omitempty" yaml:"-"` // FIXME(tsileo): ref shouldn't be a string in BlobStash response
	Meta      map[string]interface{} `json:"meta,omitempty" yaml:"meta,omitempty"`
}

type BlobYAMLHeader struct {
	Archived bool                   `yaml:"archived"`
	Title    string                 `yaml:"title"`
	Meta     map[string]interface{} `yaml:"meta,omitempty"`
}

type BlobResponse struct {
	Blobs []*Blob `json:"data"`
}

// XXX(tsileo): tabwriter?
func fmtBlobs(blobs []*Blob, shortHashLen int) {
	buf := bytes.Buffer{}
	index := map[string]string{}
	for _, blob := range blobs {
		updated := blob.CreatedAt
		if blob.UpdatedAt != 0 {
			updated = blob.UpdatedAt
		}
		t := "[N]"
		if blob.Type == "file" {
			t = "[F]"
		}
		shortHash := blob.ID[len(blob.ID)-shortHashLen : len(blob.ID)]
		if _, ok := index[shortHash]; ok {
			fmtBlobs(blobs, shortHashLen+1)
			return
		}
		index[shortHash] = blob.ID
		buf.WriteString(fmt.Sprintf("%s  %s  %s  %s\n", time.Unix(updated, 0).Format("2006-01-02  15:04"), shortHash, t, blob.Title))
	}
	data, err := json.Marshal(index)
	if err != nil {
		panic(err)
	}
	if err := ioutil.WriteFile(filepath.Join(os.TempDir(), fmt.Sprintf("blobs_refs_index.json")), data, 0644); err != nil {
		panic(err)
	}
	fmt.Printf("%s", buf.String())
}

type editedBlob struct {
	data []byte
	path string
}

func (eb *editedBlob) remove() error {
	return os.Remove(eb.path)
}

func toEditor(id string, data []byte) (*editedBlob, error) {
	fpath := filepath.Join(cache, fmt.Sprintf("blob_%s", id))

	// Ensure we won't overwrite a file that need to be recovered
	if _, err := os.Stat(fpath); !os.IsNotExist(err) {
		return nil, errCacheFileExist
	}

	if err := ioutil.WriteFile(fpath, data, 0640); err != nil {
		return nil, fmt.Errorf("failed to create temp file: %s", err)
	}

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

	// The editor has been closed, read the file back
	data2, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, fmt.Errorf("failed to open temp file: %s", err)
	}

	// The called will be responsible for removing the file
	return &editedBlob{
		path: fpath,
		data: data2,
	}, nil
}

func dataToBlob(data []byte) (*Blob, error) {
	parts := bytes.Split(data, []byte("---\n"))
	if len(parts) != 3 {
		return nil, fmt.Errorf("missing YAML header")
	}
	header := &BlobYAMLHeader{}
	if err := yaml.Unmarshal(parts[1], &header); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}
	return &Blob{
		Type:     "note",
		Archived: header.Archived,
		Title:    header.Title,
		Meta:     header.Meta,
		Content:  string(parts[2]),
	}, nil
}

type searchQuery struct {
	Fields      []string `json:"fields"`
	QueryString string   `json:"qs"`
}

func main() {
	// TODO(tsileo) config file with server address and collection name
	opts := docstore.DefaultOpts().SetHost(os.Getenv("BLOBS_API_HOST"), os.Getenv("BLOBS_API_KEY"))
	ds := docstore.New(opts)
	col := ds.Col("notes21")
	flag.Usage = Usage
	flag.Parse()

	if flag.NArg() < 1 {
		Usage()
		os.Exit(2)
	}

	var err error
	// Init cache
	cache, err = cacheDir()
	if err != nil {
		fmt.Printf("failed to init cache dir: %v", err)
		os.Exit(1)
	}

	// Try to load the previous shortID cache index if present
	index := map[string]string{}
	orig, err := ioutil.ReadFile(filepath.Join(os.TempDir(), fmt.Sprintf("blobs_refs_index.json")))
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	} else {
		if orig != nil && len(orig) > 0 {
			if err := json.Unmarshal(orig, &index); err != nil {
				panic(err)
			}
		}
	}
	expand := func(id string) string {
		if expanded, ok := index[id]; ok {
			return expanded
		}
		return id
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
		// FIXME(tsileo): an option to display full hash
		fmtBlobs(resp.Blobs, 3)

	case "search", "s":
		if flag.Arg(1) == "" {
			fmt.Printf("no query")
			return
		}
		iter, err := col.Iter(&docstore.Query{
			StoredQuery: "blobs-search",
			StoredQueryArgs: &searchQuery{
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
		fmtBlobs(resp.Blobs, 3)

	case "edit", "e":
		blob := &Blob2{}
		if err := col.GetID(expand(flag.Arg(1)), &blob); err != nil {
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
		updatedBlob, err := dataToBlob(data.data)
		if err != nil {
			panic(err)
		}

		// Ensure the blob has been modified
		if updatedBlob.Title != blob.Title || updatedBlob.Content != blob.Content {
			if err := col.UpdateID(blob.ID, updatedBlob); err != nil {
				panic(err)
			}
		}

		// Now we can safely delete the temp file
		if err := data.remove(); err != nil {
			panic(err)
		}
		// fmt.Printf("blob=%+v", updatedBlob)

	case "new", "n":
		out := []byte("---\nupdated: false\ntitle: Untitled\n---\n")
		data, err := toEditor(fmt.Sprintf("%d", time.Now().Unix()), out)
		if err != nil {
			panic(err)
		}
		updatedBlob, err := dataToBlob(data.data)
		if err != nil {
			panic(err)
		}

		// TODO(tsileo): a warning on empty notes?
		// if updatedBlob.Content == "" {}

		_id, err := col.Insert(updatedBlob, nil)
		if err != nil {
			panic(err)
		}

		// Now we can safely delete the temp file
		if err := data.remove(); err != nil {
			panic(err)
		}

		fmt.Printf("Blob %s created", _id.String())

	case "download", "dl":
		blob := &Blob2{}
		if err := col.GetID(expand(flag.Arg(1)), &blob); err != nil {
			panic(err)
		}
		if blob.Type != "file" {
			panic("not a file")
		}
		parts := strings.Split(blob.Ref, ":")
		if err := ds.DownloadAttachment(parts[1], blob.Title); err != nil {
			panic(err)
		}

		fmt.Printf("Blob downloaded at %s", blob.Title)

	case "upload", "u":
		// FIXME(tsileo): iter over all `flag.Arg(x)` and support tagging them?
		ref, err := ds.UploadAttachment(flag.Arg(1))
		if err != nil {
			panic(err)
		}
		blob := &Blob2{
			Title: filepath.Base(flag.Arg(1)),
			Type:  "file",
			Ref:   "#blobstash/json:" + ref,
		}
		_id, err := col.Insert(blob, nil)
		if err != nil {
			// FIXME(tsileo): display the ref of the attachment so a note can be created without re-uploading it
			panic(err)
		}
		fmt.Printf("Blob %s created", _id.String())

	case "convert":
		orig, err := ioutil.ReadFile(flag.Arg(1))
		if err != nil {
			panic(err)
		}
		title := filepath.Base(flag.Arg(1))
		out := []byte(fmt.Sprintf("---\narchived: false\ntitle: '%s'\n---\n", title))
		out = append(out, orig...)
		data, err := toEditor(fmt.Sprintf("%d", time.Now().Unix()), out)
		if err != nil {
			panic(err)
		}

		updatedBlob, err := dataToBlob(data.data)
		if err != nil {
			panic(err)
		}

		_id, err := col.Insert(updatedBlob, nil)
		if err != nil {
			panic(err)
		}

		// Now we can safely delete the temp file
		if err := data.remove(); err != nil {
			panic(err)
		}

		fmt.Printf("Blob %s created", _id.String())

	case "restore":
		d, err := os.Open(cache)
		if err != nil {
			printErr("failed to open cache dir", err)
		}
		fis, err := d.Readdir(-1)
		if err != nil {
			printErr("failed to read cache dir", err)
		}
		for _, fi := range fis {
			if strings.HasPrefix(fi.Name(), "blob_") {

				// buf.WriteString(fmt.Sprintf("%s  %s  %s  %s\n", time.Unix(updated, 0).Format("2006-01-02  15:04"), shortHash, t, blob.Title))

			}
		}
		if err := d.Close(); err != nil {
			printErr("failed to close cache dir", err)
		}

	default:
		Usage()
	}
}
