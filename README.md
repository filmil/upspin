# Upspin (maintained)

[![Bazel Build and Test](https://github.com/filmil/upspin/actions/workflows/bazel.yml/badge.svg)](https://github.com/filmil/upspin/actions/workflows/bazel.yml)
[![Tag and Release](https://github.com/filmil/upspin/actions/workflows/tag-and-release.yml/badge.svg)](https://github.com/filmil/upspin/actions/workflows/tag-and-release.yml)
[![Publish to my Bazel registry](https://github.com/filmil/upspin/actions/workflows/publish.yml/badge.svg)](https://github.com/filmil/upspin/actions/workflows/publish.yml)
[![Publish on Bazel Central Registry](https://github.com/filmil/upspin/actions/workflows/publish-bcr.yml/badge.svg)](https://github.com/filmil/upspin/actions/workflows/publish-bcr.yml)

**2026-04-18 update: Reviving Upspin source code**

I am reviving the Upspin source code in this repository. The goal is to keep the project building with modern tools (like [bazel](https://bazel.build)), and provide a working environment for those who still find Upspin's concepts valuable.

The code has been modified from its fork point as follows:
* Added `local_keyserver` which can be used to host a keyserver at `key.yourdomain.com`, and modified the libraries to look up keys for `youruser@yourdomain.com` on `key.yourdomain.com` instead of `key.upspin.io`. The keyserver is read-only and hosts from a static
key file. This is not intended for new users, but can be used if you already have upspin keys you want to re-activate.
* Added a release process based on GitHub workflows, replacing the custom build infra for upsping which is no longer operational.
* Moved the build system to `bazel` so that I can reuse the canned rules to manage software lifecycle.
* Revived `upspinserver-gdrive` at https://github.com/filmil/upspin-gdrive, by updating the OAuth2 flow and adding build and release infra.

Read more [here](https://hdlfactory.com/post/2026/04/19/respin-upspin-revival/).

---
Original README.md below.
---

2025-02-11 announcement: Turning down Upspin infrastructure 

Upspin, like Unix and Plan 9, was intended to foster communities of sharing, but has been less successful at that than we hoped. As a consequence, with regret, we have decided to turn down the central infrastructure such as the keyserver over the coming months 

On March 4, we will turn off keyserver for a week. This warns even people not following this list that something is happening. Then on May 6, we will turn it off permanently. If this will cause more pain than we're aware, please email grosse@gmail.com and let's discuss options.

There is much about Upspin that still seems attractive compared to alternatives. The combination of strong end-to-end encryption with the convenience of upspinfs letting you run existing apps effortlessly has been great. Bringing the idea of automatic nightly snapshots from Plan 9 to modern systems also feels great in use.

Contributors have also proposed valuable improvements, and a backlog has developed on reviewing and installing these, which is part of what prompted this decision. Some examples are: switching from a central keyserver to ssh-like authorized_keys files in clients and dirservers, revised API for Block unpacking enabling parallel reads, a clearer model for permissions on Access and Group files, and post-quantum-cryptographic packing that can defend against future rogue governments. The question is whether the size of the community justifies the effort.

We thank all who tried out Upspin!

Andrew, Dave, Eric, and Rob

-----------------------------------

# Upspin

<img alt="Augie" src="doc/images/augie-transparent.png" width=360>

Documentation: [upspin.io](https://upspin.io/)

## About the project

Upspin is an experimental project to build a framework for naming
and sharing files and other data securely, uniformly, and globally:
a global name system of sorts.

It is not a file system, but a set of protocols and reference
implementations that can be used to join things like file systems
and other storage services to the name space.

Performance is not a primary goal. Uniformity and security are.

Upspin is not an official Google product.


## Status

Upspin has rough edges, and is not yet suitable for non-technical users.

[![Build Status](https://travis-ci.org/upspin/upspin.svg?branch=master)](https://travis-ci.org/upspin/upspin)


## Contributing

The code repository lives at [GitHub](https://github.com/upspin/upspin).

See the [Contribution Guidelines](CONTRIBUTING.md)
for more information on contributing to the project.


### Reporting issues

Please report issues through
[our issue tracker](https://github.com/upspin/upspin/issues).


## Community

All Upspin users should subscribe to the
[Upspin Announcements mailing list](https://groups.google.com/forum/#!forum/upspin-announce)
to receive critical information about the project.

Use the [Upspin mailing list](https://groups.google.com/forum/#!forum/upspin)
for discussion about Upspin use and development.

## Containers

The project provides a minimal container image containing all Upspin binaries.

### Building the image

To build the container image locally:

```bash
bazel build //containers:image
```

### Pushing the image

To push the image to Docker Hub (requires being logged in):

```bash
bazel run //containers:push
```


### Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CONDUCT.md).
By participating in this project you agree to abide by its terms.


The Upspin mascot is Copyright 2017 Renee French. [All Rights Reserved](doc/mascot.md).
