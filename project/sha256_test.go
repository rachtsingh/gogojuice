// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SHA256 hash algorithm.  See FIPS 180-2.

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
)

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		s := fmt.Sprintf("%x", sha256.Sum256([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum256 function: sha256(%s) = %s want %s", g.in, s, g.out)
		}
		c := sha256.New()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sha256[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
	for i := 0; i < len(golden224); i++ {
		g := golden224[i]
		s := fmt.Sprintf("%x", sha256.Sum224([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum224 function: sha224(%s) = %s want %s", g.in, s, g.out)
		}
		c := sha256.New224()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sha224[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestSize(t *testing.T) {
	c := sha256.New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, sha256.Size)
	}
	c = sha256.New224()
	if got := c.Size(); got != Size224 {
		t.Errorf("New224.Size = %d; want %d", got, sha256.Size224)
	}
}

func TestBlockSize(t *testing.T) {
	c := sha256.New()
	if got := c.BlockSize(); got != sha256.BlockSize {
		t.Errorf("BlockSize = %d want %d", got, sha256.BlockSize)
	}
}

var bench = New()
var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}
