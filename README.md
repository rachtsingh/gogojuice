Note: this is an infected version of the Go compiler, named Gogojuice. It
modifies several library functions and is able to self-replicate when
bootstrap compiling on other Go compilers. Simply build Gogojuice from src
as you would normally, and use the resulting binary as GOROOT\_BOOTSTRAP
to build self-replicated copies!

The important code is in src/cmd/go/build.go. We also wrote a quine generator
in quine\_str.py that takes in a Go file and produces the string necessary
to produce a quine.

# The Go Programming Language

Go is an open source programming language that makes it easy to build simple,
reliable, and efficient software.

![Gopher image](doc/gopher/fiveyears.jpg)

For documentation about how to install and use Go,
visit https://golang.org/ or load doc/install-source.html
in your web browser.

Our canonical Git repository is located at https://go.googlesource.com/go.
There is a mirror of the repository at https://github.com/golang/go.

Go is the work of hundreds of contributors. We appreciate your help!

To contribute, please read the contribution guidelines:
	https://golang.org/doc/contribute.html

##### Note that we do not accept pull requests and that we use the issue tracker for bug reports and proposals only. Please ask questions on https://forum.golangbridge.org or https://groups.google.com/forum/#!forum/golang-nuts.

Unless otherwise noted, the Go source files are distributed
under the BSD-style license found in the LICENSE file.

--

## Binary Distribution Notes

If you have just untarred a binary Go distribution, you need to set
the environment variable $GOROOT to the full path of the go
directory (the one containing this file).  You can omit the
variable if you unpack it into /usr/local/go, or if you rebuild
from sources by running all.bash (see doc/install-source.html).
You should also add the Go binary directory $GOROOT/bin
to your shell's path.

For example, if you extracted the tar file into $HOME/go, you might
put the following in your .profile:

	export GOROOT=$HOME/go
	export PATH=$PATH:$GOROOT/bin

See https://golang.org/doc/install or doc/install.html for more details.
