package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"context"
	"github.com/google/subcommands"
	"github.com/mitchellh/go-homedir"
	"github.com/tsileo/blobstash/pkg/client/docstore"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

// TODO(tsileo): use JSONPatch, ETag, and ask for password on encrypted file

// The length of the salt used for scrypt.
const saltLength = 24

// The length of the nonce used for the secretbox implementation.
const nonceLength = 24

// The length of the encryption key for the secretbox implementation.
const keyLength = 32

func getPass() ([]byte, error) {
	fmt.Printf("password:")
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Printf("\n")
	if err != nil {
		return nil, err
	}
	return pass, nil
}

func key(password []byte) ([]byte, []byte, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Reader.Read(salt[:]); err != nil {
		return nil, nil, err
	}
	key, err := scrypt.Key(password, salt[:], 16384, 8, 1, keyLength)
	if err != nil {
		return nil, nil, err

	}
	return key, salt, nil
}

func seal(password, data []byte) ([]byte, error) {
	key, salt, err := key(password)
	nkey := new([keyLength]byte)
	copy(nkey[:], key)
	if err != nil {
		return nil, err
	}
	nonce := new([nonceLength]byte)
	if _, err := rand.Reader.Read(nonce[:]); err != nil {
		return nil, err
	}
	box := make([]byte, saltLength+nonceLength)
	copy(box, salt[:])
	copy(box[saltLength:], nonce[:])
	return secretbox.Seal(box, data, nonce, nkey), nil
}

func open(password, data []byte) ([]byte, error) {
	salt := new([saltLength]byte)
	copy(salt[:], data[:saltLength])
	key, err := scrypt.Key(password, salt[:], 16384, 8, 1, keyLength)
	if err != nil {
		return nil, err
	}
	nkey := new([keyLength]byte)
	copy(nkey[:], key)
	if err != nil {
		return nil, err
	}
	nonce := new([nonceLength]byte)
	copy(nonce[:], data[saltLength:(saltLength+nonceLength)])
	box := data[(saltLength + nonceLength):]
	decrypted, success := secretbox.Open(nil, box, nonce, nkey)
	if !success {
		return nil, errors.New("failed to decrypt file (bad password?)")
	}
	return decrypted, nil
}

var cache string

var errCacheFileExist = errors.New("cache file already exist")

func printErr(msg string, err error) {
	fmt.Printf("%s: %v", msg, err)
	os.Exit(1)
	// TODO(tsileo): returns the Exit...
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
	saveBlob func(*Blob, *Blob) (string, error)
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
	blob := &Blob{}
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
	saveBlob func(*Blob, *Blob) (string, error)
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

type downloadCmd struct {
	stdout  bool
	decrypt bool

	col    *docstore.Collection
	expand func(string) string
	ds     *docstore.DocStore
}

func (*downloadCmd) Name() string     { return "download" }
func (*downloadCmd) Synopsis() string { return "Download files to the current working directory" }
func (*downloadCmd) Usage() string {
	return `download <id1 id2 ...> :
	Download files to the current directory.
`
}

func (d *downloadCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&d.stdout, "stdout", false, "output the file content to stdout (only works on 1 file)")
	f.BoolVar(&d.decrypt, "decrypt", false, "decrypt the file locally")
}

func (d *downloadCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var r io.Reader
	var pwd []byte
	var err error
	if d.decrypt {
		pwd, err = getPass()
		if err != nil {
			panic(err)
		}
	}

	if d.stdout && f.NArg() > 1 {
		fmt.Printf("can only print one file to stdout")
		return subcommands.ExitFailure

	}
	for _, id := range f.Args() {
		blob := &Blob{}
		if err := d.col.GetID(d.expand(id), &blob); err != nil {
			panic(err)
		}
		if blob.Type != "file" {
			panic("not a file")
		}
		ref := blob.Ref.(map[string]interface{})["hash"].(string)
		r, err = d.ds.DownloadAttachment(ref)
		if err != nil {
			fmt.Printf("dl error=%v", err)

			return subcommands.ExitFailure
		}

		if pwd != nil && len(pwd) > 0 {
			box, err := ioutil.ReadAll(r)
			if err != nil {
				panic(err)

			}
			plain, err := open(pwd, box)
			if err != nil {
				panic(err)

			}
			r = bytes.NewReader(plain)
		}
		// FIXME(tsileo): ensure the file exists, and provide a -filename flag, even -stdout?
		// FIXME(tsileo): read the meta filename instead
		if d.stdout {
			data, err := ioutil.ReadAll(r)
			if err != nil {
				panic(err)

			}
			fmt.Printf("%s", data)
			return subcommands.ExitSuccess
		}
		output, err := os.Create(blob.Title)
		if err != nil {
			fmt.Printf("create err=%v", err)
			return subcommands.ExitFailure
		}
		defer output.Close()
		if _, err := io.Copy(output, r); err != nil {
			fmt.Printf("copy err=%v", err)
			return subcommands.ExitFailure
		}
		fmt.Printf("Blob downloaded at %s", blob.Title)
	}
	return subcommands.ExitSuccess

}

type uploadCmd struct {
	encrypt bool

	col *docstore.Collection
	ds  *docstore.DocStore
}

func (*uploadCmd) Name() string     { return "upload" }
func (*uploadCmd) Synopsis() string { return "Upload the given files" }
func (*uploadCmd) Usage() string {
	return `upload </path/to/file1 /file2 ...>:
	Upload the given files..
`
}

func (u *uploadCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&u.encrypt, "encrypt", false, "encrypt the file locally before uploading")
}

func (u *uploadCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var r io.Reader
	var pwd []byte
	var err error
	if u.encrypt {
		pwd, err = getPass()
		if err != nil {
			panic(err)
		}
	}
	var mdata map[string]interface{}
	// TODO(tsileo): support the -filename and -title flag (only for single upload)
	// TODO(tsileo): suport the -prefix/-suffix flag (for single and bulk upload)
	for _, path := range f.Args() {
		r, err = os.Open(path)
		if ff, ok := r.(io.Closer); ok {
			defer ff.Close()
		}
		if err != nil {
			return subcommands.ExitFailure
		}
		if pwd != nil && len(pwd) > 0 {
			data, err := ioutil.ReadAll(r)
			if err != nil {
				panic(err)
			}
			box, err := seal(pwd, data)
			if err != nil {
				panic(err)
			}

			r = bytes.NewReader(box)
			mdata = map[string]interface{}{
				"encrypted": true,
			}
		}
		// TODO(tsileo): support encryption
		ref, err := u.ds.UploadAttachment(filepath.Base(path), r, mdata)
		if err != nil {
			fmt.Printf("err=%v", err)
			return subcommands.ExitFailure
		}
		blob := &Blob{
			Title: filepath.Base(path),
			Type:  "file",
			Ref:   "#blobstash/json:" + ref,
		}
		_id, err := u.col.Insert(blob, nil)
		if err != nil {
			// FIXME(tsileo): display the ref of the attachment so a note can be created without re-uploading it
			panic(err)
		}
		fmt.Printf("Blob %s created", _id.String())

	}

	return subcommands.ExitSuccess
}

type convertCmd struct {
	saveBlob func(*Blob, *Blob) (string, error)
}

func (*convertCmd) Name() string     { return "convert" }
func (*convertCmd) Synopsis() string { return "Create a new blob using the file content" }
func (*convertCmd) Usage() string {
	return `convert <path> <path> <...>:
  Print args to stdout.
`
}

func (*convertCmd) SetFlags(_ *flag.FlagSet) {}

func (c *convertCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	// FIXME(tsileo): allow to convert multiple files without opening them
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

	_id, err := c.saveBlob(updatedBlob, nil)
	if err != nil {
		panic(err)
	}

	// Now we can safely delete the temp file
	if err := data.remove(); err != nil {
		panic(err)
	}

	fmt.Printf("Blob %s created", _id)

	return subcommands.ExitSuccess
}

type recoverCmd struct {
	saveBlob func(*Blob, *Blob) (string, error)
}

func (*recoverCmd) Name() string     { return "recover" }
func (*recoverCmd) Synopsis() string { return "List or recover a Blob" }
func (*recoverCmd) Usage() string {
	return `recover [<id>]:
	List or recover a Blob.
`
}

func (*recoverCmd) SetFlags(_ *flag.FlagSet) {}

func (r *recoverCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	// Recover a single Blob
	if flag.NArg() == 1 {
		data, err := ioutil.ReadFile(filepath.Join(cache, fmt.Sprintf("blob_%s", flag.Arg(1))))
		switch {
		case os.IsNotExist(err):
			fmt.Printf("No such blob to recover")
			return subcommands.ExitSuccess
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

		if _, err := r.saveBlob(updatedBlob, nil); err != nil {
			panic(err)
		}

		// Now we can safely delete the temp file
		if err := data2.remove(); err != nil {
			panic(err)
		}

		_id, err := r.saveBlob(updatedBlob, nil)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Blob %s recovered and saved", _id)
		return subcommands.ExitSuccess
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
	Ref       interface{}            `json:"_ref" yaml:"-"`
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
		t := "[N] "
		if blob.Type == "file" {
			// FIXME(tsileo): make the docstore fetch the meta even in query/list mode and support the E flag fo encrypted
			t = "[F] "
			if d, ok := blob.Ref.(map[string]interface{})["data"]; ok {
				if e, ok := d.(map[string]interface{})["encrypted"]; ok && e.(bool) {
					t = "[EF]"
				}
			}
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
	col := ds.Col("notes22")

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

	saveBlob := func(blob *Blob, prevBlob *Blob) (string, error) {
		fmt.Printf("saveBlob(%+v, %+v)\n", blob, prevBlob)
		// Blob update handling
		if prevBlob != nil && prevBlob.ID != "" {
			fmt.Printf("update")
			// Ensure the blob has been modified
			if blob.Title != prevBlob.Title || blob.Content != prevBlob.Content {
				fmt.Printf("updated %s %+v", prevBlob.ID, blob)
				// FIXME(tsileo): use patch instead
				return prevBlob.ID, col.UpdateID(prevBlob.ID, blob)
			}
			return prevBlob.ID, nil
		}

		fmt.Println("new")
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
	subcommands.Register(&convertCmd{
		saveBlob: saveBlob,
	}, "")
	subcommands.Register(&recoverCmd{
		saveBlob: saveBlob,
	}, "")
	subcommands.Register(&downloadCmd{
		col:    col,
		ds:     ds,
		expand: expand,
	}, "")
	subcommands.Register(&uploadCmd{
		col: col,
		ds:  ds,
	}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
