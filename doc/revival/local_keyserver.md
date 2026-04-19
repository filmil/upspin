# Local Keyserver

The `local_keyserver` command provides a way to run a read-only, in-process keyserver that loads its user records from a static JSON file. This is useful for testing or localized environments where a full, remote keyserver isn't necessary.

## Usage

To start the local keyserver, provide the path to your JSON keys file using the `-json` flag:

```bash
local_keyserver -json=/path/to/keys.json -http=:8080
```

## JSON Format

The expected JSON format matches the `KeyData` structure used by the in-process key implementation:

```json
{
  "Users": [
    {
      "Name": "user@example.com",
      "PublicKey": "p256\n1042304928340...",
      "Dirs": ["remote,dir.example.com:443"],
      "Stores": ["remote,store.example.com:443"]
    }
  ]
}
```

## Domain Redirection

Additionally, the `bind` package has been updated so that any client lookups for users belonging to the `domain.com` domain will be automatically redirected to a dedicated keyserver at `key.domain.com:443`.

## Configuration and Running

To run the `local_keyserver`, you need to compile it using Bazel and then execute it, providing a valid configuration and the required JSON file.

### Prerequisites

1.  **JSON File**: Create a file named `keys.json` following the format above.
2.  **Config File**: Ensure you have an Upspin configuration file (e.g., at `/home/filmil/upspin/config`).

### Building and Running

You can build and run the server using Bazel:

```bash
# Build the binary
bazel build //cmd/local_keyserver

# Run the binary
# Replace <path_to_keys.json> with the actual path
bazel run //cmd/local_keyserver -- -json=<path_to_keys.json> -http=:8080
```

Alternatively, after building, you can run the binary directly from the `bazel-bin` directory:

```bash
./bazel-bin/cmd/local_keyserver/local_keyserver_/local_keyserver -json=keys.json -http=:8080
```

You can verify it's running by curling the HTTP endpoint (if configured without TLS) or by using the `upspin` command-line tool with a config that points its `keyserver` to the local address.
