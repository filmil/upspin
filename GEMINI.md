# Instructions

Firstly, read README.md to understand how to build and what the purpose of
things is.

Never auto-modify the following files:
* //tools/bazel
* Any dotfile.
* Any `*.lock` files.
* Any `*.nix` files.

Unless otherwise instructed, only apply maintenance tasks to files in the git
index, or uncommitted files, to avoid redoing work on files that are already
committed to git.

# General change rules

Read the file `//docs/AI_GIT.md` for instructions.

# Documentation

Use Doxygen rules for documenting.

Whenever you add Doxygen documentation, also add the source filegroup targets ,
or source files where filegroups are unavailable, to the `srcs` attribute of
the `doxygen` target named "//:docs", so that doxygen docs could be updated
too. Include all VHDL files, but also C headers, and any other program source
files which contain documentation.

Do not run buildifier, as it will mess up the VHDL file ordering.

When updating documentation run `bazel build //:docs` to verify that it is
correct.

# License maintenance

When maintaining the license files do not modify the following:

* Files matching `*.gtkw`.
* Files under the directory `//third_party`.
* Any files with filenames beginning with a dot.

For all source files and all BUILD files, verify that they have a license
reference at the beginning of the file.

If a file does not have a license reference, add the following text in the
header, appropriately enclosed in comments that are appropriate for the
source file type in question:

```
SPDX-License-Identifier: Apache-2.0
```

# `//third_party` maintenance

Every subdir under `//third_party` must have a LICENSE file with the appropriate
license copied from its source distribution.

# Public API documentation maintenance

Ensure that the repository is clean before starting this procedure.

For all source files, we want to maintain an up-to-date documentation of their
respective public API.

# Bazel build instructions

This project uses Bazel for building and testing.

## Building and Testing

To build the whole project:
```bash
bazel build //...
```

To run all tests:
```bash
bazel test //...
```

**CRITICAL RULE:** You must run all tests (`bazel test //...`) after making any code changes to ensure no regressions are introduced before concluding the task.

## Maintenance with Gazelle

We use Gazelle to automatically generate and update `BUILD.bazel` files.

### Updating BUILD files

After adding new Go files or changing imports, run:
```bash
bazel run //:gazelle
```

### Adding new dependencies

1. Add the dependency to `go.mod` (e.g., using `go get`).
2. Update the `MODULE.bazel` file to include the new repository in `use_repo` if it's a direct dependency.
3. Run `bazel mod tidy` to update `MODULE.bazel.lock` and potentially `MODULE.bazel`.

### Proto Files

Proto generation is currently disabled in Gazelle (`# gazelle:proto disable` in the root `BUILD.bazel`) because the project uses checked-in `.pb.go` files. If you add new proto files, you should generate the `.pb.go` files manually or re-enable proto generation and resolve any conflicts.

# Publish to Bazel central registry

Read the file `//docs/AI_BCR.md` for publication instructions.
