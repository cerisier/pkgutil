# pkgutil

Cross-platform reimplementation of Apple’s `pkgutil` (macOS), with a focus on
making `.pkg` extraction work on other platforms.

## Supported commands

Currently:
- `--expand`
- `--expand-full`

Both work for component packages and product archives.

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
