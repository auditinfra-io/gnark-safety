module example.com/toolchainfixture

go 1.21

// No such release exists. Under GOTOOLCHAIN=auto the go command would try
// to download and run it.
toolchain go1.99.0
