# pkgutil

[![pkgutil-tests](https://github.com/cerisier/pkgutil/actions/workflows/test.yml/badge.svg)](https://github.com/cerisier/pkgutil/actions/workflows/test.yml)

Cross-platform reimplementation of Apple’s `pkgutil` (macOS), with a focus on
making `.pkg` extraction work on other platforms.

## Usage
```
Usage: pkgutil [OPTIONS] [COMMANDS] ...

Options:
  --help                 Show this usage guide
  --verbose, -v          Show contextual information and format for easy reading
  --force, -f            Perform all operations without asking for confirmation
  --include PATTERN      Only include paths matching PATTERN
  --exclude PATTERN      Exclude paths matching PATTERN
  --strip-components N   Strip N leading path components

File Commands:
  --expand PKG DIR       Write flat package entries to DIR
  --expand-full PKG DIR  Fully expand package contents to DIR
```

## Limitations

Only extraction of `.pkg` is supported for the moment.
Both for component packages and product archives.

## Design choices

- Use libarchive as much as possible.
- Threat all `.pkg` XAR entries normally expect for well known nested archives
   like `Payload` and `Scripts` (only expanded in `--expand-full`)

## libarchive pbzx support

Some `Payload` entries are wrapped in Apple’s `pbzx`. 
For this, we add `pbzx` support to `libarchive` as a patch for now, to deframe 
`pbzx` streams so the usual archive readers like `cpio` can parse the content.

## Build

```sh
bazel build //:pkgutil
```

## Example

```sh
bazel-bin/pkgutil --expand-full path/to/pkg.pkg outdir
```
