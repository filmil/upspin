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

# Source control guidance


- Prefer rebase over merge: `git pull origin main --rebase`.
- PRs should be created against the `main` branch.
- Before creating PRs, rebase from main, and fix any conflicts.
- When resolving conflicts, use the `--no-edit` git option to prevent
  interactive editor invocations.
- Use "Conventional Commits 1.0.0" for commit messages.


# License maintenance

When maintaining the license files do not modify the following:

* Files under the directory `//third_party`.
* Any files with filenames beginning with a dot.

For all source files and all BUILD files, verify that they have a license
reference at the beginning of the file.

If a file does not have a license reference, add the following text in the
header, appropriately enclosed in comments that are appropriate for the source
file type in question:

``` SPDX-License-Identifier: Apache-2.0 ```



# `//third_party` maintenance

Every subdir under `//third_party` must have a LICENSE file with the
appropriate license copied from its source distribution.



# Public API documentation maintenance

Ensure that the repository is clean before starting this procedure.

For all source files, we want to maintain an up-to-date documentation of their
respective public API.



# Bazel build instructions

This project uses Bazel for building and testing.

- **Primary Language:** Go.
- **Commands:**
  - **NEVER** run `go` directly.
    Always use `bazel run @rules_go//go -- <args>`.
  - Use `bazel run //:gazelle` to update build rules.
  - Use `bazel mod tidy` to update `MODULE.bazel`.
  - Build: `bazel build //...`
  - Test: `bazel test //...`
- To manipulate bazel BUILD files with buildozer, use
  `bazel run @buildozer -- ARGS`
- **DO NOT** downgrade dependencies. If a downgrade is needed, stop and ask the
  user for permission.


## Building and Testing

To build the whole project: ```bash bazel build //... ```

To run all tests: ```bash bazel test //... ```

**CRITICAL RULE:** You must run all tests (`bazel test //...`) after making any
code changes to ensure no regressions are introduced before concluding the
task.


### Adding new dependencies

1. Add the dependency to `go.mod`.
2. Update the `MODULE.bazel` file to include the new repository in `use_repo`
   if it's a direct dependency.
3. Run `bazel mod tidy` to update `MODULE.bazel.lock` and potentially
   `MODULE.bazel`.

### Proto Files

Proto generation is currently disabled in Gazelle (`# gazelle:proto disable` in
the root `BUILD.bazel`) because the project uses checked-in `.pb.go` files. If
you add new proto files, you should generate the `.pb.go` files manually or
re-enable proto generation and resolve any conflicts.


## Engineering Standards

- **Error Handling:** Never ignore errors. Propagate them with context or log
  them explicitly.
- Every ferature MUST have unit tests.
- Large features MUST have integration tests.
- After every feature implementation, build and run tests to verify
  functionality and prevent regressions.


## Workspace Conventions

- Use "Conventional Commits 1.0.0" for commit messages.


## CI/CD

- CI runs on GitHub Actions (Ubuntu).
- Uses Bazel caching (`~/.cache/bazel-disk-cache`,
  `~/.cache/bazel-repository-cache`).


