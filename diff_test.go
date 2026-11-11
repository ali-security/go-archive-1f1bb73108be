package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/go-archive/compression"
)

func TestApplyLayerInvalidFilenames(t *testing.T) {
	for i, headers := range [][]*tar.Header{
		{
			{
				Name:     "../victim/dotdot",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
		{
			{
				// Note the leading slash
				Name:     "/../victim/slash-dotdot",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
	} {
		if err := testBreakout("applylayer", "docker-TestApplyLayerInvalidFilenames", headers); err != nil {
			t.Fatalf("i=%d. %v", i, err)
		}
	}
}

func TestApplyLayerInvalidHardlink(t *testing.T) {
	for i, headers := range [][]*tar.Header{
		{ // try reading victim/hello (../)
			{
				Name:     "dotdot",
				Typeflag: tar.TypeLink,
				Linkname: "../victim/hello",
				Mode:     0o644,
			},
		},
		{ // try reading victim/hello (/../)
			{
				Name:     "slash-dotdot",
				Typeflag: tar.TypeLink,
				// Note the leading slash
				Linkname: "/../victim/hello",
				Mode:     0o644,
			},
		},
		{ // try writing victim/file
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeLink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "loophole-victim/file",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
		{ // try reading victim/hello (hardlink, symlink)
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeLink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "symlink",
				Typeflag: tar.TypeSymlink,
				Linkname: "loophole-victim/hello",
				Mode:     0o644,
			},
		},
		{ // Try reading victim/hello (hardlink, hardlink)
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeLink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "hardlink",
				Typeflag: tar.TypeLink,
				Linkname: "loophole-victim/hello",
				Mode:     0o644,
			},
		},
		{ // Try removing victim directory (hardlink)
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeLink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
	} {
		if err := testBreakout("applylayer", "docker-TestApplyLayerInvalidHardlink", headers); err != nil {
			t.Fatalf("i=%d. %v", i, err)
		}
	}
}

func TestApplyLayerInvalidSymlink(t *testing.T) {
	for i, headers := range [][]*tar.Header{
		{ // try reading victim/hello (../)
			{
				Name:     "dotdot",
				Typeflag: tar.TypeSymlink,
				Linkname: "../victim/hello",
				Mode:     0o644,
			},
		},
		{ // try reading victim/hello (/../)
			{
				Name:     "slash-dotdot",
				Typeflag: tar.TypeSymlink,
				// Note the leading slash
				Linkname: "/../victim/hello",
				Mode:     0o644,
			},
		},
		{ // try writing victim/file
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeSymlink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "loophole-victim/file",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
		{ // try reading victim/hello (symlink, symlink)
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeSymlink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "symlink",
				Typeflag: tar.TypeSymlink,
				Linkname: "loophole-victim/hello",
				Mode:     0o644,
			},
		},
		{ // try reading victim/hello (symlink, hardlink)
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeSymlink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "hardlink",
				Typeflag: tar.TypeLink,
				Linkname: "loophole-victim/hello",
				Mode:     0o644,
			},
		},
		{ // try removing victim directory (symlink)
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeSymlink,
				Linkname: "../victim",
				Mode:     0o755,
			},
			{
				Name:     "loophole-victim",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
	} {
		if err := testBreakout("applylayer", "docker-TestApplyLayerInvalidSymlink", headers); err != nil {
			t.Fatalf("i=%d. %v", i, err)
		}
	}
}

// TestApplyLayerInvalidWhiteout verifies that a whiteout for ".." (".wh...")
// cannot be used to remove the parent directory of the extraction root, and
// everything in it.
func TestApplyLayerInvalidWhiteout(t *testing.T) {
	for i, headers := range [][]*tar.Header{
		{ // try removing the parent of dest, including victim
			{
				Name:     WhiteoutPrefix + "..",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
		{ // try removing the parent of dest, including victim (leading slash)
			{
				Name:     "/" + WhiteoutPrefix + "..",
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			},
		},
	} {
		if err := testBreakout("applylayer", "docker-TestApplyLayerInvalidWhiteout", headers); err != nil {
			t.Fatalf("i=%d. %v", i, err)
		}
	}
}

// TestUnpackLayerWhiteoutDestContained verifies that a whiteout cannot be used
// to remove the extraction root itself.
func TestUnpackLayerWhiteoutDestContained(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
	}{
		{name: "dot", entry: WhiteoutPrefix + "."},
		{name: "empty", entry: WhiteoutPrefix},
		{name: "nested dotdot", entry: "dir/" + WhiteoutPrefix + ".."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := t.TempDir()
			if err := os.Mkdir(filepath.Join(dest, "dir"), 0o755); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dest, "marker")
			if err := os.WriteFile(marker, []byte("marker"), 0o644); err != nil {
				t.Fatal(err)
			}

			buf := &bytes.Buffer{}
			tw := tar.NewWriter(buf)
			if err := tw.WriteHeader(&tar.Header{
				Name:     tc.entry,
				Typeflag: tar.TypeReg,
				Mode:     0o644,
			}); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}

			_, err := UnpackLayer(dest, buf, &TarOptions{NoLchown: true})
			if err == nil || !strings.Contains(err.Error(), "invalid whiteout entry") {
				t.Fatalf("expected invalid whiteout entry error, got: %v", err)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("archive breakout: extraction root removed: %v", err)
			}
		})
	}
}

func TestApplyLayerWhiteouts(t *testing.T) {
	wd, err := os.MkdirTemp("", "graphdriver-test-whiteouts")
	if err != nil {
		return
	}
	defer os.RemoveAll(wd)

	base := []string{
		".baz",
		"bar/",
		"bar/bax",
		"bar/bay/",
		"baz",
		"foo/",
		"foo/.abc",
		"foo/.bcd/",
		"foo/.bcd/a",
		"foo/cde/",
		"foo/cde/def",
		"foo/cde/efg",
		"foo/fgh",
		"foobar",
	}

	type tcase struct {
		change, expected []string
	}

	tcases := []tcase{
		{
			change:   base,
			expected: base,
		},
		{
			change: []string{
				".bay",
				".wh.baz",
				"foo/",
				"foo/.bce",
				"foo/.wh..wh..opq",
				"foo/cde/",
				"foo/cde/efg",
			},
			expected: []string{
				".bay",
				".baz",
				"bar/",
				"bar/bax",
				"bar/bay/",
				"foo/",
				"foo/.bce",
				"foo/cde/",
				"foo/cde/efg",
				"foobar",
			},
		},
		{
			change: []string{
				".bay",
				".wh..baz",
				".wh.foobar",
				"foo/",
				"foo/.abc",
				"foo/.wh.cde",
				"bar/",
			},
			expected: []string{
				".bay",
				"bar/",
				"bar/bax",
				"bar/bay/",
				"foo/",
				"foo/.abc",
				"foo/.bce",
			},
		},
		{
			change: []string{
				".abc",
				".wh..wh..opq",
				"foobar",
			},
			expected: []string{
				".abc",
				"foobar",
			},
		},
	}

	for i, tc := range tcases {
		l, err := makeTestLayer(tc.change)
		if err != nil {
			t.Fatal(err)
		}

		_, err = UnpackLayer(wd, l, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = l.Close()
		if err != nil {
			t.Fatal(err)
		}

		paths, err := readDirContents(wd)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(tc.expected, paths) {
			t.Fatalf("invalid files for layer %d: expected %q, got %q", i, tc.expected, paths)
		}
	}
}

type readCloserWrapper struct {
	io.Reader
	closer func() error
}

func (r *readCloserWrapper) Close() error {
	if r.closer != nil {
		return r.closer()
	}
	return nil
}

func makeTestLayer(paths []string) (_ io.ReadCloser, retErr error) {
	tmpDir, err := os.MkdirTemp("", "graphdriver-test-mklayer")
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			os.RemoveAll(tmpDir)
		}
	}()
	for _, p := range paths {
		// Source files are always in Unix format. But we use filepath on
		// creation to be platform agnostic.
		if p[len(p)-1] == '/' {
			if err = os.MkdirAll(filepath.Join(tmpDir, p), 0o700); err != nil {
				return nil, err
			}
		} else {
			if err = os.WriteFile(filepath.Join(tmpDir, p), nil, 0o600); err != nil {
				return nil, err
			}
		}
	}
	archive, err := Tar(tmpDir, compression.None)
	if err != nil {
		return nil, err
	}
	return &readCloserWrapper{
		Reader: archive,
		closer: func() error {
			err := archive.Close()
			os.RemoveAll(tmpDir)
			return err
		},
	}, nil
}

func readDirContents(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			rel = rel + string(filepath.Separator)
		}
		// Append in Unix semantics
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
