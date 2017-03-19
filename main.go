package main

import (
	"bufio"
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
	"text/tabwriter"
	"time"

	"a4.io/blobstash/pkg/client/docstore"
	"context"
	"github.com/google/subcommands"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

// TODO(tsileo): use JSONPatch, ETag
// FIXME(tsileo): ability to pipe commands redis-cli like

// The length of the salt used for scrypt.
const saltLength = 24

// The length of the nonce used for the secretbox implementation.
const nonceLength = 24

// The length of the encryption key for the secretbox implementation.
const keyLength = 32

// Set a flag to identify the encryption algorithm in case we support/switch encryption scheme later
const (
	naclSecretBox byte = 1 << iota
)

// getPass display the password input
func getPass() ([]byte, error) {
	fmt.Printf("password:")
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Printf("\n")
	if err != nil {
		return nil, err
	}
	return pass, nil
}

// key returns the key, along with the salt
func key(password []byte) ([]byte, []byte, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Reader.Read(salt[:]); err != nil {
		return nil, nil, err
	}
	// TODO(tsileo): make the scrypt parameters constant
	key, err := scrypt.Key(password, salt[:], 16384, 8, 1, keyLength)
	if err != nil {
		return nil, nil, err

	}
	return key, salt, nil
}

// Seal the data with the key derived from `password` (using scrypt) and seal the data with nacl/secretbox
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
	// Box will contains our meta data (alg byte + salt + nonce)
	box := make([]byte, saltLength+nonceLength+1)
	// Store the alg byte
	box[0] = naclSecretBox
	// The salt
	copy(box[1:], salt[:])
	// And the nonce
	copy(box[saltLength+1:], nonce[:])
	return secretbox.Seal(box, data, nonce, nkey), nil
}

// Open a previously sealed secretbox with the key derived from `password` (using scrypt)
func open(password, data []byte) ([]byte, error) {
	if data[0] != naclSecretBox {
		return nil, fmt.Errorf("invalid/unsupported encryption scheme: %v", data[0]) // XXX(tsileo): is scheme the right word?
	}
	// Extract the salt
	salt := new([saltLength]byte)
	copy(salt[:], data[1:saltLength+1])
	// Re-derivate the key
	key, err := scrypt.Key(password, salt[:], 16384, 8, 1, keyLength)
	if err != nil {
		return nil, err
	}
	nkey := new([keyLength]byte)
	copy(nkey[:], key)
	if err != nil {
		return nil, err
	}
	// Extract the nonce
	nonce := new([nonceLength]byte)
	copy(nonce[:], data[saltLength+1:(saltLength+nonceLength+1)])
	box := data[(saltLength + nonceLength + 1):]
	// Actually decrypt the cipher text
	decrypted, success := secretbox.Open(nil, box, nonce, nkey)

	// Ensure the decryption succeed
	if !success {
		return nil, errors.New("failed to decrypt file (bad password?)")
	}

	return decrypted, nil
}

var cache string

var errCacheFileExist = errors.New("cache file already exist")

func rerr(msg string, a ...interface{}) subcommands.ExitStatus {
	fmt.Printf(msg, a...)
	return subcommands.ExitFailure
}

func rsuccess(msg string, a ...interface{}) subcommands.ExitStatus {
	fmt.Printf(msg, a...)
	return subcommands.ExitSuccess
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

type echoCmd struct {
	expand func(string) string
}

func (*echoCmd) Name() string     { return "echo" }
func (*echoCmd) Synopsis() string { return "echo" }
func (*echoCmd) Usage() string {
	return `echo :
	Echo.
`
}

func (*echoCmd) SetFlags(_ *flag.FlagSet) {}

func (e *echoCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	ids := IDsFromStdin(e.expand)
	if ids != nil {
		for _, id := range ids {
			fmt.Printf("id=%s\n", id)
		}
	}
	return subcommands.ExitSuccess
}

// IDsFromStdin reads the output of a previous commands and returns the blob IDs.
// $ blobs search tag:mytag type:file | blobs download -
func IDsFromStdin(expandFunc func(string) string) []string {
	var ids []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		data := strings.Split(scanner.Text(), "\t")
		if len(data) < 2 {
			break
		}
		ids = append(ids, expandFunc(data[1]))
	}
	return ids
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
	iter, err := r.col.Iter(nil, &docstore.IterOpts{Limit: 10})
	if err != nil {
		return rerr("failed to call BlobStash: %v", err)
	}
	resp := &BlobsResponse{}
	iter.Next(resp)
	if err := iter.Err(); err != nil {
		return rerr("iteration error: %v", err)
	}
	// FIXME(tsileo): an option to display full hash
	resp.parsePointers()
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
	// FIXME(tsileo) f.Arg(0) instead of flag.Arg(1)
	if flag.Arg(1) == "" {
		return rsuccess("missing query")
	}
	iter, err := s.col.Iter(&docstore.Query{
		StoredQuery: "blobs-search",
		StoredQueryArgs: &searchQuery{
			Fields:      []string{"title", "content"},
			QueryString: flag.Arg(1),
		},
	}, nil)
	if err != nil {
		return rerr("failed to execute BlobStash query: %v", err)
	}
	resp := &BlobsResponse{}
	iter.Next(resp)
	if err := iter.Err(); err != nil {
		return rerr("iterator error: %v", err)
	}
	resp.parsePointers()
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
	blobResp := &BlobResponse{}
	if err := e.col.GetID(e.expand(flag.Arg(1)), &blobResp); err != nil {
		return rerr("failed to retrieve document from BlobStash: %v", err)
	}
	blobResp.parsePointers()
	blob := blobResp.Blob
	if blob.Kind != "note" {
		return rerr("blob is not a note, got \"%s\"", blob.Kind)
	}
	out := []byte("---\n")
	d, err := yaml.Marshal(blob)
	if err != nil {
		return rerr("failed to marshal blob as JSON: %v", err)
	}
	out = append(out, d...)
	out = append(out, []byte("---\n")...)
	out = append(out, []byte(blob.Content)...)
	data, err := toEditor(blob.ID, out, true)
	if err != nil {
		return rerr("failed to edit blob: %v", err)
	}
	updatedBlob, err := dataToBlob(data.data)
	if err != nil {
		return rerr("failed to unserialize blob: %v", err)
	}

	if _, err := e.saveBlob(updatedBlob, blob); err != nil {
		return rerr("failed to save blob: %v", err)
	}

	// Now we can safely delete the temp file
	if err := data.remove(); err != nil {
		return rerr("failed to remove temporary file: %v", err)
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
		return rerr("failed to edit blob: %v", err)
	}
	updatedBlob, err := dataToBlob(data.data)
	if err != nil {
		return rerr("failed to unserialize blob: %v", err)
	}

	// TODO(tsileo): a warning on empty notes?
	// if updatedBlob.Content == "" {}

	_id, err := n.saveBlob(updatedBlob, nil)
	if err != nil {
		return rerr("failed to save blob: %v", err)
	}

	// Now we can safely delete the temp file
	if err := data.remove(); err != nil {
		return rerr("failed to remove temporary file: %v")
	}

	fmt.Printf("Blob %s created", _id)
	return subcommands.ExitSuccess

}

type downloadCmd struct {
	stdout  bool
	decrypt bool // Optional in case one's want to download the file encrypted? XXX(ts): worth it?

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
			return rerr("failed to read password: %v", err)
		}
	}

	if d.stdout && f.NArg() > 1 {
		fmt.Printf("can only print one file to stdout")
		return subcommands.ExitFailure

	}
	for _, id := range f.Args() {
		blobResp := &BlobResponse{}
		if err := d.col.GetID(d.expand(id), &blobResp); err != nil {
			return rerr("failed to fetch document from BlobStash: %v", err)
		}
		fmt.Printf("br=%+v\n", blobResp)
		blobResp.parsePointers()
		blob := blobResp.Blob
		if blob.Kind != "file" {
			return rerr("blob is not a file, got \"%s\"", blob.Kind)
		}
		ref := blob.File["hash"].(string)
		r, err = d.ds.DownloadAttachment(ref)
		if err != nil {
			fmt.Printf("dl error=%v", err)

			return subcommands.ExitFailure
		}

		if pwd != nil && len(pwd) > 0 {
			box, err := ioutil.ReadAll(r)
			if err != nil {
				return rerr("failed to read attachment: %v", err)
			}
			plain, err := open(pwd, box)
			if err != nil {
				// TODO(tsileo): handle the bad password error with a custom error message
				return rerr("failed to decrypt file: %v", err)

			}
			r = bytes.NewReader(plain)
		}
		// FIXME(tsileo): ensure the file exists, and provide a -filename flag, even -stdout?
		// FIXME(tsileo): read the meta filename instead
		if d.stdout {
			data, err := ioutil.ReadAll(r)
			if err != nil {
				return rerr("failed to read file: %v", err)

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
	encrypt  bool
	filename string
	title    string
	prefix   string
	suffix   string

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
	f.StringVar(&u.filename, "filename", "", "override the filename (dont't work with bulk uploads)")
	f.StringVar(&u.prefix, "prefix", "", "prepend the prefix to filenames")
	f.StringVar(&u.suffix, "suffix", "", "append the suffix to filenames") // XXX(tsileo): check the spelling of suffix?
}

func (u *uploadCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var r io.Reader
	var pwd []byte
	var err error
	if u.encrypt {
		pwd, err = getPass()
		if err != nil {
			return rerr("failed to get password: %s", err)
		}
	}

	// Quick check
	if f.NArg() > 1 && (u.filename != "" || u.title != "") {
		return rerr("-filename and -title cant be used for bulk uploads")
	}

	for _, path := range f.Args() {
		var mdata map[string]interface{}
		r, err = os.Open(path)
		if ff, ok := r.(io.Closer); ok {
			defer ff.Close()
		}
		if err != nil {
			return rerr("failed to open file at %s: %s", path, err)
		}
		if pwd != nil && len(pwd) > 0 {
			data, err := ioutil.ReadAll(r)
			if err != nil {
				return rerr("failed to read file at %s: %s", path, err)
			}
			box, err := seal(pwd, data)
			if err != nil {
				return rerr("failed to encrypt file at %s: %s", path, err)
			}

			r = bytes.NewReader(box)
			mdata = map[string]interface{}{
				"encrypted": true,
			}
		}
		fname := filepath.Base(path)

		fmt.Printf("u=%+v", u)

		if u.prefix != "" || u.suffix != "" {
			fname = u.prefix + fname + u.suffix
		}

		// Override the filename if the flag is set
		if u.filename != "" {
			fname = u.filename
		}

		ref, err := u.ds.UploadAttachment(fname, r, mdata)
		if err != nil {
			// XXX(tsileo): in this case, there won't be any reference to it if the upload is not retried
			return rerr("failed to upload file at %s: %s", path, err)
		}
		// Now we can create the Blob
		blob := &Blob{
			Title: fname,
			Kind:  "file",
			Ref:   "@filetree/ref:" + ref,
		}
		_id, err := u.col.Insert(blob, nil)
		if err != nil {
			// FIXME(tsileo): display the ref of the attachment so a note can be created without re-uploading it?
			return rerr("failed to create blob: %s", err)
		}
		fmt.Printf(_id.String())
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
	Convert the content of the given files as Blobs.
`
}

func (*convertCmd) SetFlags(_ *flag.FlagSet) {}

func (c *convertCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	// FIXME(tsileo): allow to convert multiple files without opening them
	orig, err := ioutil.ReadFile(flag.Arg(1))
	if err != nil {
		return rerr("failed to read source file (\"%s\"): %v", flag.Arg(1), err)
	}
	title := filepath.Base(flag.Arg(1))
	out := []byte(fmt.Sprintf("---\narchived: false\ntitle: '%s'\n---\n", title))
	out = append(out, orig...)
	data, err := toEditor(fmt.Sprintf("%d", time.Now().Unix()), out, true)
	if err != nil {
		return rerr("failed to edit blob: %v", err)
	}

	updatedBlob, err := dataToBlob(data.data)
	if err != nil {
		return rerr("failed to unserialize blob: %v", err)
	}

	_id, err := c.saveBlob(updatedBlob, nil)
	if err != nil {
		return rerr("failed to save blob: %v", err)
	}

	// Now we can safely delete the temp file
	if err := data.remove(); err != nil {
		return rerr("failed to remove temporary file: %v", err)
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
			return rerr("no such blob")
		case err == nil:
		default:
			return rerr("failed to read source file: %v", err)
		}

		data2, err := toEditor(flag.Arg(1), data, false)
		if err != nil {
			return rerr("failed to edit blob: %v", err)
		}
		updatedBlob, err := dataToBlob(data2.data)
		if err != nil {
			return rerr("failed to unserialize blob: %v", err)
		}

		_id, err := r.saveBlob(updatedBlob, nil)
		if err != nil {
			return rerr("failed to save blob: %v", err)
		}

		// Now we can safely delete the temp file
		if err := data2.remove(); err != nil {
			return rerr("failed to remove temporary file: %v", err)
		}

		fmt.Printf("Blob %s recovered and saved", _id)
		return subcommands.ExitSuccess
	}

	// List all blobs available for recovery
	d, err := os.Open(cache)
	if err != nil {
		return rerr("failed to open cache dir: %v", err)
	}
	fis, err := d.Readdir(-1)
	if err != nil {
		return rerr("failed to read cache dir: %v", err)
	}
	buf := &bytes.Buffer{}
	for _, fi := range fis {
		if strings.HasPrefix(fi.Name(), "blob_") {
			data, err := ioutil.ReadFile(filepath.Join(cache, fi.Name()))
			if err != nil {
				return rerr("failed to read restore file: %v", err)
			}
			blob, err := dataToBlob(data)
			if err != nil {
				return rerr("file looks corrupted: %v", err)
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
		return rerr("failed to close cache dir: %v", err)
	}
	return subcommands.ExitSuccess
}

type FileRef struct {
	Hash string `json:"hash"`
}

// TODO(tsileo): make Blob.Created() (time.Time, error) / Updated
type Blob struct {
	CreatedAt string                 `json:"_created,omitempty" yaml:"-"`
	Hash      string                 `json:"_hash,omitempty" yaml:"-"`
	ID        string                 `json:"_id,omitempty" yaml:"_id"`
	Kind      string                 `json:"kind" yaml:"-"`
	UpdatedAt string                 `json:"_updated,omitempty" yaml:"-"`
	Archived  bool                   `json:"archived" yaml:"archived"`
	Tags      []string               `json:"tags" yaml:"tags"`
	Content   string                 `json:"content" yaml:"-"`
	Title     string                 `json:"title" yaml:"title"`
	Meta      map[string]interface{} `json:"meta,omitempty" yaml:"meta,omitempty"`
	Ref       string                 `json:"ref" yaml:"-"`
	File      map[string]interface{} `json:"-" yaml:"-"`
}

func (b *Blob) Created() (time.Time, error) {
	var t time.Time
	if b.CreatedAt == "" {
		return t, nil
	}
	created, err := time.Parse(time.RFC3339, b.CreatedAt)
	if err != nil {
		return t, err
	}
	return created, nil
}

func (b *Blob) Updated() (time.Time, error) {
	var t time.Time
	if b.UpdatedAt == "" {
		return b.Created()
	}
	updated, err := time.Parse(time.RFC3339, b.UpdatedAt)
	if err != nil {
		return t, err
	}
	return updated, nil
}

type BlobYAMLHeader struct {
	Archived bool                   `yaml:"archived"`
	Title    string                 `yaml:"title"`
	Meta     map[string]interface{} `yaml:"meta,omitempty"`
	Tags     []string               `yaml:"tags"`
}

type BlobsResponse struct {
	Blobs    []*Blob                           `json:"data"`
	Pointers map[string]map[string]interface{} `json:"pointers"`
	// TODO(tsileo): handle pagination
}

func (br *BlobsResponse) parsePointers() {
	for _, b := range br.Blobs {
		if ref, ok := br.Pointers[b.Ref]; ok {
			b.File = ref
		}
	}
}

type BlobResponse struct {
	Blob     *Blob                             `json:"data"`
	Pointers map[string]map[string]interface{} `json:"pointers"`
	// TODO(tsileo): handle pagination
}

func (br *BlobResponse) parsePointers() {
	fmt.Printf("blob=%+v\n", br.Blob)
	if ref, ok := br.Pointers[br.Blob.Ref]; ok {
		br.Blob.File = ref
		fmt.Printf("f=%+v\n", br.Blob.File)
	}
}

func fmtBlobs(blobs []*Blob, shortHashLen int) error {
	w := new(tabwriter.Writer)
	// Format in tab-separated columns with a tab stop of 8.
	w.Init(os.Stdout, 0, 8, 0, '\t', 0)
	// fmt.Fprintln(w, "a\tb\tc\td\t.")

	// buf := bytes.Buffer{}
	index := map[string]string{}
	for _, blob := range blobs {
		updated, err := blob.Updated()
		if err != nil {
			return err
		}
		t := "[N] "
		if blob.Kind == "file" {
			t = "[F] "
			if d, ok := blob.File["data"]; ok {
				if e, ok := d.(map[string]interface{})["encrypted"]; ok && e.(bool) {
					t = "[EF]"
				}
			}
		}
		shortHash := blob.ID[len(blob.ID)-shortHashLen : len(blob.ID)]
		if _, ok := index[shortHash]; ok {
			return fmtBlobs(blobs, shortHashLen+1)
		}
		index[shortHash] = blob.ID
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", updated.Format("2006-01-02  15:04"), shortHash, t, blob.Title)
	}

	data, err := json.Marshal(index)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(os.TempDir(), fmt.Sprintf("blobs_refs_index.json")), data, 0644); err != nil {
		return err
	}
	// fmt.Fprintln(w, "123\t12345\t1234567\t123456789\t.")
	fmt.Fprintln(w)
	w.Flush()
	return nil
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
		Kind:     "note",
		Archived: header.Archived,
		Title:    header.Title,
		Tags:     header.Tags,
		Meta:     header.Meta,
		Content:  string(parts[2]),
	}, nil
}

type searchQuery struct {
	Fields      []string `json:"fields"`
	QueryString string   `json:"qs"`
}

func getExpander() (func(string) string, error) {
	// Try to load the previous shortID cache index if present
	index := map[string]string{}
	orig, err := ioutil.ReadFile(filepath.Join(os.TempDir(), fmt.Sprintf("blobs_refs_index.json")))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	} else {
		if orig != nil && len(orig) > 0 {
			if err := json.Unmarshal(orig, &index); err != nil {
				return nil, err
			}
		}
	}
	expand := func(id string) string {
		if expanded, ok := index[id]; ok {
			return expanded
		}
		return id
	}
	return expand, nil
}

func main() {
	// TODO(tsileo) config file with server address and collection name
	opts := docstore.DefaultOpts().SetHost(os.Getenv("BLOBS_API_HOST"), os.Getenv("BLOBS_API_KEY"))
	ds := docstore.New(opts)
	col := ds.Col("notes23")

	var err error
	// Init cache
	cache, err = cacheDir()
	if err != nil {
		fmt.Printf("failed to init cache dir: %v", err)
		os.Exit(1)
	}

	expand, err := getExpander()
	if err != nil {
		fmt.Printf("failed to load short IDs index: %v", err)
		os.Exit(1)
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
	// subcommands.Register(&echoCmd{
	// 	expand: expand,
	// }, "")
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
