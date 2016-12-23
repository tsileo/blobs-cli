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

	"context"
	"github.com/google/subcommands"
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

type recentCmd struct {
	col *docstore.Collection
}

func (*recentCmd) Name() string     { return "recent" }
func (*recentCmd) Synopsis() string { return "Display recent blobs" }
func (*recentCmd) Usage() string {
	return `recent :
	Display recent blobs.
`
}

func (*recentCmd) SetFlags(_ *flag.FlagSet) {}

func (r *recentCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	iter, err := r.col.Iter(nil, nil)
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

	return subcommands.ExitSuccess
}

type searchCmd struct {
	col *docstore.Collection
}

func (*searchCmd) Name() string     { return "search" }
func (*searchCmd) Synopsis() string { return "Search blobs" }
func (*searchCmd) Usage() string {
	return `search <query>:
	Search blobs.
`
}

func (*searchCmd) SetFlags(_ *flag.FlagSet) {}

func (s *searchCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if flag.Arg(1) == "" {
		fmt.Printf("no query")
		return subcommands.ExitSuccess
	}
	iter, err := s.col.Iter(&docstore.Query{
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
	return subcommands.ExitSuccess
}

type editCmd struct {
	col      *docstore.Collection
	expand   func(string) string
	saveBlob func(*Blob, *Blob2) (string, error)
}

func (*editCmd) Name() string     { return "edit" }
func (*editCmd) Synopsis() string { return "Edit a blob" }
func (*editCmd) Usage() string {
	return `edit <id>:
	Spawn $EDITOR to edit the blob.
`
}

func (*editCmd) SetFlags(_ *flag.FlagSet) {}

func (e *editCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	blob := &Blob2{}
	if err := e.col.GetID(e.expand(flag.Arg(1)), &blob); err != nil {
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
	data, err := toEditor(blob.ID, out, true)
	if err != nil {
		panic(err)
	}
	updatedBlob, err := dataToBlob(data.data)
	if err != nil {
		panic(err)
	}

	if _, err := e.saveBlob(updatedBlob, blob); err != nil {
		panic(err)
	}

	// Now we can safely delete the temp file
	if err := data.remove(); err != nil {
		panic(err)
	}
	return subcommands.ExitSuccess
}

type newCmd struct {
	col      *docstore.Collection
	saveBlob func(*Blob, *Blob2) (string, error)
}

func (*newCmd) Name() string     { return "new" }
func (*newCmd) Synopsis() string { return "Create a new blob" }
func (*newCmd) Usage() string {
	return `new :
	Create a new blob.
`
}

func (*newCmd) SetFlags(_ *flag.FlagSet) {}

func (n *newCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	out := []byte("---\nupdated: false\ntitle: Untitled\n---\n")
	data, err := toEditor(fmt.Sprintf("%d", time.Now().Unix()), out, true)
	if err != nil {
		panic(err)
	}
	updatedBlob, err := dataToBlob(data.data)
	if err != nil {
		panic(err)
	}

	// TODO(tsileo): a warning on empty notes?
	// if updatedBlob.Content == "" {}

	_id, err := n.saveBlob(updatedBlob, nil)
	if err != nil {
		panic(err)
	}

	// _id, err := col.Insert(updatedBlob, nil)
	// if err != nil {
	// 	panic(err)
	// }

	// Now we can safely delete the temp file
	if err := data.remove(); err != nil {
		panic(err)
	}

	fmt.Printf("Blob %s created", _id)
	return subcommands.ExitSuccess
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

func toEditor(id string, data []byte, existCheck bool) (*editedBlob, error) {
	fpath := filepath.Join(cache, fmt.Sprintf("blob_%s", id))

	if existCheck {
		// Ensure we won't overwrite a file that need to be recovered
		if _, err := os.Stat(fpath); !os.IsNotExist(err) {
			return nil, errCacheFileExist
		}
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

	saveBlob := func(blob *Blob, prevBlob *Blob2) (string, error) {
		// Blob update handling
		if blob.ID != "" {
			// Ensure the blob has been modified
			if prevBlob == nil || blob.Title != prevBlob.Title || blob.Content != prevBlob.Content {
				return "", col.UpdateID(blob.ID, blob)
			}
		}

		// New blob handling
		_id, err := col.Insert(blob, nil)
		if err != nil {
			return "", err
		}

		// No ID, it must be a new Blob
		return _id.String(), nil
	}

	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	// subcommands.Register(&printCmd{}, "")
	subcommands.Register(&recentCmd{col}, "")
	subcommands.Register(&searchCmd{col}, "")
	subcommands.Register(&editCmd{
		col:      col,
		saveBlob: saveBlob,
		expand:   expand,
	}, "")
	subcommands.Register(&newCmd{
		col:      col,
		saveBlob: saveBlob,
	}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))

	switch flag.Arg(0) {
	case "edit", "e":
	case "new", "n":
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
		data, err := toEditor(fmt.Sprintf("%d", time.Now().Unix()), out, true)
		if err != nil {
			panic(err)
		}

		updatedBlob, err := dataToBlob(data.data)
		if err != nil {
			panic(err)
		}

		_id, err := saveBlob(updatedBlob, nil)
		if err != nil {
			panic(err)
		}

		// Now we can safely delete the temp file
		if err := data.remove(); err != nil {
			panic(err)
		}

		fmt.Printf("Blob %s created", _id)

	case "recover":
		// Recover a single Blob
		if flag.NArg() == 2 {
			data, err := ioutil.ReadFile(filepath.Join(cache, fmt.Sprintf("blob_%s", flag.Arg(1))))
			switch {
			case os.IsNotExist(err):
				fmt.Printf("No such blob to recover")
				return
			case err == nil:
			default:
				panic(err)
			}

			data2, err := toEditor(flag.Arg(1), data, false)
			if err != nil {
				panic(err)
			}
			updatedBlob, err := dataToBlob(data2.data)
			if err != nil {
				panic(err)
			}

			if _, err := saveBlob(updatedBlob, nil); err != nil {
				panic(err)
			}

			// Now we can safely delete the temp file
			if err := data2.remove(); err != nil {
				panic(err)
			}

			_id, err := saveBlob(updatedBlob, nil)
			if err != nil {
				panic(err)
			}

			fmt.Printf("Blob %s recovered and saved", _id)
			return
		}

		// List all blobs available for recovery
		d, err := os.Open(cache)
		if err != nil {
			printErr("failed to open cache dir", err)
		}
		fis, err := d.Readdir(-1)
		if err != nil {
			printErr("failed to read cache dir", err)
		}
		buf := &bytes.Buffer{}
		for _, fi := range fis {
			if strings.HasPrefix(fi.Name(), "blob_") {
				data, err := ioutil.ReadFile(filepath.Join(cache, fi.Name()))
				if err != nil {
					printErr("failed to read restore file", err)
				}
				blob, err := dataToBlob(data)
				if err != nil {
					printErr("file looks corrupted", err)
				}
				blobID := blob.ID
				// If there's no ID yet, use the timsetamp as ID instead
				flag := "[N] "
				if blobID == "" {
					n := fi.Name()
					blobID = fi.Name()[5:len(n)]
					flag = "[UN]"
				}
				// TODO(tsileo): tabwriter
				buf.WriteString(fmt.Sprintf("%s  %s  %s  %s\n", fi.ModTime().Format("2006-01-02  15:04"), blobID, flag, blob.Title))
			}
		}
		fmt.Printf(buf.String())
		if err := d.Close(); err != nil {
			printErr("failed to close cache dir", err)
		}

	default:
	}
}
