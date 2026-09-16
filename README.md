# OPC UA Assessment Toolkit

A single, consolidated tool for assessing the security of OPC UA servers. It
merges three previously separate pieces of tooling into one entry point:

- a **scanner** for discovering servers and enumerating their endpoint
  configuration and node access control,
- a **writer** for changing node values with automatic data-type handling,
- an **interactive console** for hands-on browsing, reading, writing and
  method calls.

The toolkit supports **both** a non-interactive command-line workflow (for
scripting, automation and reproducible assessments) and an **interactive**
console workflow (for exploratory testing). Both modes share the same
connection, authentication, channel-security and type-coercion code, so they
behave identically against a target.

> **Authorised use only.** This is a security-assessment tool intended for use
> against systems you own or are explicitly authorised to test. Writing to
> nodes on a live OPC UA server can affect a physical process. Do not point it
> at systems you do not have permission to assess.

## Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Quick start](#quick-start)
5. [Non-interactive mode](#non-interactive-mode)
   - [hello — discovery](#hello--discovery)
   - [server_config — configuration & access control](#server_config--configuration--access-control)
   - [read_data — read node values](#read_data--read-node-values)
   - [write_data — write node values](#write_data--write-node-values)
6. [Interactive mode](#interactive-mode)
7. [Authentication & channel security](#authentication--channel-security)
8. [Exit codes](#exit-codes)
9. [Project layout](#project-layout)
10. [Author](#author)
11. [Contributors](#contributors)
12. [Acknowledgements](#acknowledgements)
13. [License](#license)

## Features

- **Unified entry point** (`opcua_toolkit.py`) exposing every capability as a
  subcommand.
- **Server discovery** with HEL/ACK probing across IP ranges and port ranges.
- **Endpoint & security enumeration**: security modes, policies, accepted
  authentication types, and the servers a target knows about.
- **Access-control assessment**: find writable nodes and executable methods,
  optionally starting from a chosen root node.
- **Typed writing with verification**: the value's type is auto-detected from
  the target node (or forced with `-dt`), then the write is confirmed by
  reading the value back. Booleans, signed/unsigned integers, `Float`/`Double`,
  `String`, `ByteString`, `DateTime` and `Guid` are all supported.
- **Interactive console** to browse the address space, read/write nodes, call
  methods and inspect node attributes live.
- **Full authentication support** in both modes: Anonymous, Username/Password,
  and X.509 Certificate, plus `Sign` / `SignAndEncrypt` channel security with a
  configurable security policy.
- **Scripting-friendly**: the non-interactive commands work correctly when
  piped or run from automation (they do not depend on an interactive TTY) and
  return a meaningful process exit code (see
  [Exit codes](#exit-codes)).

## Requirements

- Python 3.8+
- The Python packages listed in [`requirements.txt`](requirements.txt):
  `asyncua`, `cryptography`, `tabulate`.

## Installation

```bash
# from the repository root
pip3 install -r requirements.txt
```

Then make the entry point executable (optional):

```bash
chmod +x opcua_toolkit.py
```

You can run the tool with either `python3 opcua_toolkit.py ...` or
`./opcua_toolkit.py ...`.

## Quick start

```bash
# 1. Discover OPC UA servers on a host across a couple of ports
./opcua_toolkit.py hello -i 127.0.0.1 -p '4840, 53530'

# 2. Enumerate a server's configuration and find writable nodes
./opcua_toolkit.py server_config -t opc.tcp://127.0.0.1:4840/ -nw -ne

# 3. Read a node value
./opcua_toolkit.py read_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2003' --single

# 4. Write a node value (type auto-detected, write verified)
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2003' -d 42

# 5. Explore interactively
./opcua_toolkit.py interactive -t opc.tcp://127.0.0.1:4840/
```

Run `./opcua_toolkit.py -h`, or `./opcua_toolkit.py <command> -h`, for the full
option list of any command.

## Non-interactive mode

The non-interactive commands are designed for scripting and reproducible
assessments. Every command that connects to a server accepts the same
authentication and channel-security options (see
[Authentication & channel security](#authentication--channel-security)).

### hello — discovery

Sends OPC UA HEL/ACK messages to locate servers.

```bash
# single target
./opcua_toolkit.py hello -i 127.0.0.1 -p 53530

# multiple ports and a port range
./opcua_toolkit.py hello -i 127.0.0.1 -p '4840, 5060-5065, 53530'

# multiple hosts (ranges and CIDR are supported)
./opcua_toolkit.py hello -i '127.0.0.1-5, 10.0.0.0/30' -p 4840

# a .txt file with one host/range/CIDR per line ('#' comments allowed)
./opcua_toolkit.py hello -i targets.txt -p 4840

# store results for later use by server_config
./opcua_toolkit.py hello -i 127.0.0.1 -p 4840 -o hello_output.json
```

Host specifications accept single IPs and hostnames, comma-separated lists,
dashed IPv4 ranges (`10.0.0.1-20`), CIDR blocks and a path to a `.txt` file.

Useful options: `-n/--name` (server name in the URL, or a file of names),
`-o/--output` (save detected servers to JSON), `-t/--timeout` (per-target
timeout in ms, default 500), `-v/--verbose`, `-tfmt/--table_format`.

### server_config — configuration & access control

Gathers endpoint descriptions, accepted security and authentication options,
and (once authenticated) node access-control information.

```bash
# endpoint / security enumeration (no auth required)
./opcua_toolkit.py server_config -t opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer

# reuse the hello output as the target list
./opcua_toolkit.py server_config -t hello_output.json

# find writable nodes and executable methods (requires a successful auth)
./opcua_toolkit.py server_config -t opc.tcp://127.0.0.1:4840/ \
    -a Username -u user -p pass -nw -ne

# start the search from a specific root node
./opcua_toolkit.py server_config -t opc.tcp://127.0.0.1:4840/ -nw -r 'ns=6;s=MyObjectsFolder'
```

Useful options: `-nw/--nodes_writable`, `-ne/--nodes_executable`,
`-r/--root_node`, `-s/--servers` (list servers known by the target),
`-na/--node_attributes` (extra attributes, requires `-o`), `-o/--output_verbose`
(JSON dump), `-tfmt/--table_format`.

### read_data — read node values

```bash
# read the whole address space from the root, into a summary table
./opcua_toolkit.py read_data -t opc.tcp://127.0.0.1:4840/

# browse from a node and read the values underneath it
./opcua_toolkit.py read_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;s=Devices'

# read a single node without browsing (--single is a flag, no value)
./opcua_toolkit.py read_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2003' --single
```

### write_data — write node values

The target VariantType is detected from the node itself, so you usually only
need the node id and the value. The write is verified by reading the value
back.

```bash
# auto-detected type (works for bool / int / float / string nodes)
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2003' -d 1
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2004' -d true
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2005' -d 3.14
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2006' -d "hello"

# force a specific type if auto-detection is not what you want
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=2003' -d 42 -dt UInt16

# ByteString (hex or base64), DateTime (ISO-8601 or epoch seconds), Guid
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=10' -d 'cafebabe'
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=11' -d '2023-06-15T12:30:00'
./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ -r 'ns=2;i=12' -d '11112222-3333-4444-5555-666677778888'
```

`-r/--root_node` is required. `-dt/--dtype` accepts any scalar VariantType
name, e.g. `Boolean`, `Int16`, `Int32`, `Int64`, `UInt16`, `UInt32`, `UInt64`,
`Byte`, `SByte`, `Float`, `Double`, `String`, `ByteString`, `DateTime`, `Guid`.

## Interactive mode

The interactive console opens one connection and gives you a command loop. Any
authentication detail you do not pass on the command line is prompted for when
the console starts.

```bash
# connect with a full URL and pick auth interactively
./opcua_toolkit.py interactive -t opc.tcp://127.0.0.1:53530/OPCUA/SimulationServer

# or build the URL from parts, and pass auth up front to skip the prompts
./opcua_toolkit.py interactive --hostname 127.0.0.1 --port 4840 --path /server/ \
    -a Username -u user -p pass
```

Once connected you get an `opcua>` prompt. Available commands:

| Command | Description |
|---------|-------------|
| `read <node>` | Read a node value and its data type |
| `write <node> <value> [type]` | Write a value (type auto-detected; optional override) |
| `browse [node]` | List the children of a node (default: `objects`) |
| `info <node>` | Show a node's key attributes and access level |
| `endpoints` | List the server endpoints and their security |
| `servers` | List servers known by the target server |
| `writable [node]` | Find writable variable nodes under a subtree |
| `methods [node]` | Find callable methods under a subtree |
| `call <object> <method> [args...]` | Call a method (best-effort argument coercion) |
| `aliases` | Show the well-known node aliases |
| `help` / `menu` | Show the command help |
| `exit` / `quit` | Disconnect and leave |

Node ids can be given as a NodeId string (`ns=2;i=2003`, `ns=6;s=MyFolder`), a
bare integer (`2253`, treated as `i=2253`), or one of the well-known aliases:
`root`, `objects`, `types`, `views`, `server`.

Method-call arguments accept an optional `tag:value` type prefix so a value is
sent with the type the method expects, for example `s:0042` for the String
`"0042"` (instead of the integer 42) or `u16:7` for a `UInt16`. Tags:
`s`/`str`, `bool`, `i16`/`i32`/`i64`, `u16`/`u32`/`u64`, `byte`, `sbyte`,
`f`/`float`, `d`/`double`. Untagged arguments are guessed as bool, then int,
then float, then string.

The interactive console can also be run on its own:

```bash
./opcua_client.py --hostname 127.0.0.1 --port 4840 --path /server/
```

## Authentication & channel security

All connecting commands accept the same options:

| Option | Meaning |
|--------|---------|
| `-a/--authentication` | `Anonymous` (default), `Username`, `Certificate`, `Issued` |
| `-u/--username`, `-p/--password` | Credentials for `Username` auth |
| `-c/--certificate`, `-pk/--private_key` | Certificate and key for `Certificate` auth and/or encryption |
| `-m/--mode` | Channel security mode: `None` (default), `Sign`, `SignAndEncrypt` |
| `-po/--policy` | Security policy: `Basic128Rsa15`, `Basic256`, `Basic256Sha256`, `Aes128Sha256RsaOaep` |

When a security mode other than `None` is used, a security policy and a
certificate/key pair are required.

Example with signed-and-encrypted channel and certificate authentication:

```bash
./opcua_toolkit.py server_config -t opc.tcp://127.0.0.1:4840/ \
    -a Certificate -c certificate.pem -pk private_key.pem \
    -m SignAndEncrypt -po Basic256Sha256
```

## Exit codes

The non-interactive commands return a process exit status so they can be used
in scripts and pipelines:

| Code | Meaning |
|------|---------|
| `0` | Success: at least one target responded, or the write completed |
| `1` | Handled failure: nothing was reachable, or the operation failed |
| `2` | Usage error: missing or invalid arguments |

```bash
if ./opcua_toolkit.py hello -i 10.0.0.5 -p 4840 >/dev/null; then
    echo "server present"
fi
```

## Project layout

```
opcua-assessment-toolkit/
├── opcua_toolkit.py     # unified entry point (all commands + interactive)
├── opcua_scan.py        # non-interactive scan/read/write engine
├── opcua_client.py      # interactive console
├── requirements.txt
├── wordlist/            # well-known OPC UA endpoint names
├── LICENSE
└── README.md
```

`opcua_toolkit.py` is the recommended entry point. `opcua_scan.py` and
`opcua_client.py` remain runnable on their own for backwards compatibility and
for use as importable modules.

## Author

**d3vn0mi**

## Contributors

- **d3vn0mi**

Contributions are welcome. Please open an issue or pull request.

## Acknowledgements

The non-interactive scanning engine builds on the OPC UA assessment tooling
published by Wavestone, which in turn was inspired by the Metasploit module
[msf-opcua](https://github.com/COMSYS/msf-opcua) by Linus Roepert, Markus
Dahlmanns, Ina Berenice Fink, Jan Pennekamp and Martin Henze. Thanks to those
authors. The host/IP specification syntax is modelled on
[ipparser](https://github.com/m8sec/ipparser) by m8sec.

## License

Released under the MIT License. See [LICENSE](LICENSE).
