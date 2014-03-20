# ocaml-gsasl

This is a preliminary release of OCaml bindings for the
[GNU SASL library](http://www.gnu.org/software/gsasl/).  They are written using
[Ctypes](https://github.com/ocamllabs/ocaml-ctypes).

## Installation and Usage

1. Install `libgsasl`.  If you are using OS X with [Homebrew](http://brew.sh),
   this is as simple as typing
   ```sh
   brew install gsasl
   ```

2. Download the current version of `ocaml-gsasl`.
   ```sh
   cd ~/tmp
   git clone https://github.com/nojb/ocaml-gsasl
   ```

3. Configure, build and install (this requires `findlib`)
   ```sh
   cd ocaml-gsasl
   ./configure
   make
   make install
   ```

4. To see if it is working, you can try it out in the `ocaml` toplevel:
   ```ocaml
   # #use "topfind";;
   - : unit = ()
   # #require "gsasl";;
    # let s = Gsasl.base64_to "Hello, World!";;
   val s : string = "SGVsbG8sIFdvcmxkIQ=="
   # Gsasl.base64_from s;;
   - : string = "Hello, World!"
   # let ctx = Gsasl.init ();;
   val ctx : Gsasl.context = <abstr>
   # Gsasl.client_mechlist ctx;;
   - : string list = ["GSSAPI"; "OPENID20"; "SAML20"; "SCRAM-SHA-1"; "CRAM-MD5"; "DIGEST-MD5"; "SECURID"; "PLAIN"; "LOGIN"; "EXTERNAL"; "ANONYMOUS"]
    ```

5. Read the documentation in `lib/gsasl.mli`.

## Comments

Comments, bug reports and feature requests are very welcome: n.oje.bar@gmail.com.
