# Local Keyserver Usage

The local keyserver provides a way to run a read-only keyserver using a local file as its backing store. This is useful for testing, bootstrapping, or scenarios where a full remote keyserver is not required or desired.

## Configuration

To configure an Upspin server or client to use a local keyserver, set the `key` endpoint in your configuration file (or via the `-endpoint` flag if setting up) to use the `local` transport, pointing to the absolute path of the JSON file containing the key data.

**Example `config` file snippet:**
```
key: local,/path/to/my/local_keys.json
```

## Running the Keyserver

When starting an Upspin server (e.g., `upspinserver`), you must specify the `-kind` flag to tell it to use the local implementation.

```bash
upspinserver -kind=local -config=/path/to/config ...
```

This will instantiate a read-only `inprocess` keyserver populated with the data from the JSON file specified in the `config`.

## Data Format

The JSON file used by the local keyserver should contain a `KeyData` structure, which holds a list of `upspin.User` objects.

**Example `local_keys.json`:**
```json
{
  "Users": [
    {
      "Name": "user@example.com",
      "PublicKey": "p256\n...",
      "Dirs": [
        {"Transport": 1, "NetAddr": "remote,dir.example.com"}
      ],
      "Stores": [
        {"Transport": 1, "NetAddr": "remote,store.example.com"}
      ]
    }
  ]
}
```

## Important Notes

*   **Read-Only:** The local keyserver is strictly read-only. Any attempts to `Put` or update user data via this keyserver will result in an error indicating that it is a read-only keyserver.
*   **Binding:** When a client or server initializes its transports (via `transports.Init`), it checks if the key endpoint is `local`. If so, it reads the specified file and binds a read-only in-process keyserver to the `local` transport, allowing subsequent RPCs directed to `local` to be handled internally.
