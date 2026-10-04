# Scanning untrusted repositories

`gnark-safety` is a source analyzer, not a sandbox. `go/packages` invokes the Go
command, and Go may select a toolchain, contact a module proxy, read a populated
module cache, or process unusually large dependency graphs. Do not run the CLI
directly against hostile input with developer credentials or a writable home
directory.

## Built-in ceilings

Every scan has three independent defaults:

- `--timeout=2m` cancels package loading and AST analysis;
- `--max-hints=10000` aborts rather than returning an unbounded result set; and
- `--max-output-bytes=16777216` renders into a bounded buffer before writing to
  stdout or the requested output path.

Invalid or exceeded limits return exit code 2. Raising these values increases
resource exposure; it does not improve analysis precision. Cancellation is
cooperative—the operating system may take a short time to reap Go subprocesses.

`gnark-safety-mcp` additionally forces `GOTOOLCHAIN=local`, empties
`GOFLAGS`, and turns off the go env file, `go.work`, and cgo for every package
load, and refuses paths outside its `--root`. That removes toolchain
selection by the scanned module; it does not make the scan a sandbox.

## Recommended isolation

For an untrusted checkout, use a disposable container or VM with:

1. a read-only source mount and a separate writable temporary directory;
2. no host credentials, SSH agent, cloud metadata access, or Docker socket;
3. networking disabled, or restricted to an allowlisted and logged Go proxy;
4. a fixed `GOTOOLCHAIN` and `GOTOOLCHAIN=local` when auto-downloads are not
   intended;
5. an empty, size-limited `GOMODCACHE`, `GOCACHE`, and `GOPATH`;
6. CPU, memory, process-count, file-size, and wall-clock limits; and
7. a non-root user with a read-only root filesystem.

Pre-populate and verify the module cache in a separate trusted step if the scan
must run without a network. Do not share a writable module cache between trust
domains. Treat generated JSON and SARIF as untrusted data when importing them
into another service.

The built-in timeout and result/output limits are defense in depth. They do not
limit memory consumed by the Go compiler before it observes cancellation, and
they do not replace OS-level isolation.
