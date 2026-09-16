#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
opcua_client.py - Interactive OPC UA assessment console.

This is the interactive counterpart to the non-interactive opcua_scan
commands. It opens a single connection to an OPC UA server and gives an
operator a small command loop to browse the address space, read and write
node values (with automatic type coercion and read-back verification) and
call methods.

It reuses the connection, authentication, security and type-coercion helpers
from opcua_scan so interactive and non-interactive modes behave identically.

Run standalone:
    ./opcua_client.py --hostname 127.0.0.1 --port 53530 \
        --path /OPCUA/SimulationServer

or through the unified entry point:
    ./opcua_toolkit.py interactive -t opc.tcp://127.0.0.1:53530/OPCUA/...
"""

import argparse
import asyncio
import getpass
import os

from asyncua import Client, ua

import opcua_scan as engine


##############################################################################
#                              Input helpers                                 #
##############################################################################

async def ainput(prompt=""):
    """
    Async wrapper around input() so the event loop is not blocked while the
    operator types. Raises EOFError on end of input (e.g. piped stdin).
    """
    return (await asyncio.to_thread(input, prompt)).strip()


async def apassword(prompt="Password: "):
    """
    Like ainput(), but does not echo the typed characters to the terminal.
    Used for secrets so passwords do not end up on screen or in scrollback.
    """
    return (await asyncio.to_thread(getpass.getpass, prompt)).strip()


# Well-known node aliases so operators can type "objects" instead of "i=85".
NODE_ALIASES = {
    "root": "i=84",
    "objects": "i=85",
    "types": "i=86",
    "views": "i=87",
    "server": "i=2253",
}


# Type tags for method call arguments, e.g. `s:0042` forces the String "0042"
# instead of the integer 42, and `u16:7` forces a UInt16.
CALL_ARG_TYPE_TAGS = {
    "s": ua.VariantType.String,
    "str": ua.VariantType.String,
    "bool": ua.VariantType.Boolean,
    "i16": ua.VariantType.Int16,
    "i32": ua.VariantType.Int32,
    "i64": ua.VariantType.Int64,
    "u16": ua.VariantType.UInt16,
    "u32": ua.VariantType.UInt32,
    "u64": ua.VariantType.UInt64,
    "byte": ua.VariantType.Byte,
    "sbyte": ua.VariantType.SByte,
    "f": ua.VariantType.Float,
    "float": ua.VariantType.Float,
    "d": ua.VariantType.Double,
    "double": ua.VariantType.Double,
}


def coerce_call_arg(token):
    """
    Coerce one method-call argument. A `tag:value` prefix (see
    CALL_ARG_TYPE_TAGS) forces an explicit ua.Variant so, for example, a
    leading-zero PIN can be sent as a String rather than being turned into an
    int. Without a tag, fall back to best-effort bool/int/float/str guessing.
    """
    if ":" in token:
        tag, _, value = token.partition(":")
        vtype = CALL_ARG_TYPE_TAGS.get(tag.lower())
        if vtype is not None:
            return ua.Variant(engine.cast_to_variant(value, vtype), vtype)

    low = token.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(token)
    except ValueError:
        try:
            return float(token)
        except ValueError:
            return token


def resolve_node(client, token):
    """
    Turn an operator-supplied token into a Node. Accepts well-known aliases
    (root/objects/types/views/server), a bare integer (treated as i=<n>) or
    any standard NodeId string (e.g. ns=2;i=2003, ns=6;s=MyFolder).
    """
    token = token.strip()
    if token.lower() in NODE_ALIASES:
        token = NODE_ALIASES[token.lower()]
    if token.isdigit():
        token = f"i={token}"
    return client.get_node(token)


##############################################################################
#                          Authentication set-up                             #
##############################################################################

def build_auth_namespace(
    authentication="Anonymous", username="", password="",
    certificate="", private_key="", mode="None", policy="None"
):
    """
    Build the argparse-style namespace expected by
    engine.setup_client_for_authentication().
    """
    return argparse.Namespace(
        authentication=authentication,
        username=username or "",
        password=password or "",
        certificate=certificate or "",
        private_key=private_key or "",
        mode=mode or "None",
        policy=policy or "None",
    )


async def prompt_for_auth():
    """
    Interactively ask the operator how to authenticate. Returns a namespace
    suitable for engine.setup_client_for_authentication().
    """
    engine.pretty_log(
        "Authentication methods: "
        f"{', '.join(engine.valid_auth_methods)} (default: Anonymous)"
    )
    method = (await ainput("Authentication [Anonymous]: ")) or "Anonymous"
    method = method.capitalize()
    if method not in engine.valid_auth_methods:
        engine.pretty_log(
            f"Unknown method '{method}', falling back to Anonymous",
            lvl="critical"
        )
        method = "Anonymous"

    username = password = certificate = private_key = ""
    if method == "Username":
        username = await ainput("Username: ")
        password = await apassword("Password: ")
    elif method == "Certificate":
        certificate = await ainput("Certificate (.pem/.der) path: ")
        private_key = await ainput("Private key path: ")

    # Optional channel security (Sign / SignAndEncrypt).
    mode = policy = "None"
    want_sec = (await ainput("Configure channel security? [y/N]: ")).lower()
    if want_sec in ("y", "yes"):
        modes = ", ".join(engine.valid_security_modes.keys())
        policies = ", ".join(list(engine.valid_security_policies.keys())[1:])
        mode = (await ainput(f"Security mode ({modes}) [None]: ")) or "None"
        if mode != "None":
            policy = (await ainput(f"Security policy ({policies}): ")) or "None"
            if not certificate:
                certificate = await ainput("Certificate path (for security): ")
            if not private_key:
                private_key = await ainput("Private key path (for security): ")

    return build_auth_namespace(
        authentication=method, username=username, password=password,
        certificate=certificate, private_key=private_key,
        mode=mode, policy=policy
    )


##############################################################################
#                          Interactive console                               #
##############################################################################

HELP_TEXT = """
Available commands:
  read   <node>                 Read a node value and its data type
  write  <node> <value> [type]  Write a value (type auto-detected; optional
                                override e.g. Int32, Float, Boolean, String)
  browse [node]                 List the children of a node (default: Objects)
  info   <node>                 Show a node's key attributes
  endpoints                     List the server endpoints and their security
  servers                       List servers known by the target server
  writable [node]               Find writable variable nodes under a subtree
  methods  [node]               Find callable methods under a subtree
  call   <object> <method> [args...]
                                Call a method. Args may carry a type tag, e.g.
                                s:0042 (String), u16:7 (UInt16), bool:true
  aliases                       Show well-known node aliases
  help | menu                   Show this help
  exit | quit                   Disconnect and leave

Node forms: root | objects | types | views | server | 2253 | i=2253 |
            ns=2;i=2003 | ns=6;s=MyFolder
""".rstrip()


class OpcuaConsole:
    """
    Holds a live client connection and dispatches interactive commands.
    """

    def __init__(self, url, auth_ns):
        self.url = url
        self.auth_ns = auth_ns
        self.client = None

    async def connect(self):
        """
        Reachability precheck, security/auth set-up, then connect.
        Returns True on success.
        """
        client = Client(self.url, timeout=10)
        engine.MSG_PREFIX = ""

        engine.pretty_log(f"Target: {self.url}")
        if not await engine.precheck_connection(client):
            engine.pretty_log(
                "No OPC UA Hello/Acknowledge response from the target",
                lvl="error"
            )
            return False
        engine.pretty_log("Valid OPC UA response", lvl="success")

        # Show endpoints up front - useful reconnaissance before authenticating.
        try:
            endpoints = await engine.get_endpoints(client)
            engine.iterate_endpoints(endpoints, {"target": self.url,
                                                 "endpoints": []})
        except Exception as err:
            engine.pretty_log(f"Could not list endpoints: {err}", lvl="critical")

        if not await engine.setup_client_for_authentication(client, self.auth_ns):
            engine.pretty_log("Client authentication set-up failed", lvl="error")
            return False

        try:
            await client.connect()
        except Exception as err:
            engine.pretty_log(f"Connection failed: {err}", lvl="error")
            return False

        self.client = client
        engine.pretty_log(
            f"Connected ({self.auth_ns.authentication} authentication)",
            lvl="success"
        )
        return True

    async def disconnect(self):
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None

    # ---- individual commands -------------------------------------------- #

    async def cmd_read(self, args):
        if not args:
            engine.pretty_log("Usage: read <node>", lvl="error")
            return
        node = resolve_node(self.client, args[0])
        value = await node.read_value()
        try:
            vtype = await node.read_data_type_as_variant_type()
            vtype_name = vtype.name
        except Exception:
            vtype_name = "unknown"
        engine.pretty_log(
            f"{node.nodeid.to_string()} = "
            f"\033[92m\033[1m{value!r}\033[0m ({vtype_name})",
            lvl="success"
        )

    async def cmd_write(self, args):
        if len(args) < 2:
            engine.pretty_log(
                "Usage: write <node> <value> [type]", lvl="error"
            )
            return
        node = resolve_node(self.client, args[0])
        raw = args[1]
        dtype_override = args[2] if len(args) >= 3 else None

        # Show the current value first.
        try:
            current = await node.read_value()
            engine.pretty_log(f"Previous value: {current!r}")
        except Exception as err:
            engine.pretty_log(f"Could not read current value: {err}",
                              lvl="critical")

        try:
            value, vtype = await engine.coerce_value_for_node(
                node, raw, dtype_override
            )
        except Exception as err:
            engine.pretty_log(f"Value coercion error: {err}", lvl="error")
            return

        engine.pretty_log(f"Writing {value!r} as {vtype.name}")
        await node.set_value(ua.DataValue(ua.Variant(value, vtype)))

        # Verify.
        new_value = await node.read_value()
        if engine.values_equivalent(value, new_value):
            engine.pretty_log(
                f"Verified: {node.nodeid.to_string()} = "
                f"\033[92m\033[1m{new_value!r}\033[0m",
                lvl="success"
            )
        else:
            engine.pretty_log(
                f"Verification mismatch: expected {value!r}, "
                f"read back {new_value!r}",
                lvl="critical"
            )

    async def cmd_browse(self, args):
        target = args[0] if args else "objects"
        node = resolve_node(self.client, target)
        children = await node.get_children()
        engine.pretty_log(
            f"Children of {node.nodeid.to_string()} ({len(children)}):"
        )
        for child in children:
            try:
                bname = (await child.read_browse_name()).to_string()
            except Exception:
                bname = "?"
            try:
                nclass = engine.int_to_node_class(
                    await child.read_node_class()
                ).name
            except Exception:
                nclass = "?"
            engine.pretty_log(
                f"  {child.nodeid.to_string():<24} {nclass:<10} {bname}"
            )

    async def cmd_info(self, args):
        if not args:
            engine.pretty_log("Usage: info <node>", lvl="error")
            return
        node = resolve_node(self.client, args[0])
        engine.pretty_log(f"NodeId: {node.nodeid.to_string()}")
        for label, coro in (
            ("BrowseName", node.read_browse_name()),
            ("DisplayName", node.read_display_name()),
        ):
            try:
                engine.pretty_log(f"  {label}: {(await coro).to_string()}")
            except Exception as err:
                engine.pretty_log(f"  {label}: {err}", lvl="critical")
        try:
            nclass = engine.int_to_node_class(await node.read_node_class())
            engine.pretty_log(f"  NodeClass: {nclass.name}")
        except Exception as err:
            engine.pretty_log(f"  NodeClass: {err}", lvl="critical")
        try:
            value = await node.read_value()
            vtype = await node.read_data_type_as_variant_type()
            engine.pretty_log(f"  Value: {value!r} ({vtype.name})")
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            engine.pretty_log(f"  Value: {err}", lvl="critical")
        try:
            access = await node.get_user_access_level()
            engine.pretty_log(
                f"  UserAccessLevel: {sorted(a.name for a in access)}"
            )
        except Exception:
            pass

    async def cmd_endpoints(self, args):
        # Use the live session's channel. engine.get_endpoints() /
        # connect_and_get_server_endpoints() open AND then tear down their own
        # socket, which would drop this console's connection.
        endpoints = await self.client.get_endpoints()
        engine.iterate_endpoints(endpoints, {"target": self.url,
                                             "endpoints": []})

    async def cmd_servers(self, args):
        # find_servers() runs on the current channel; connect_and_find_servers()
        # would disconnect the live session.
        descriptions = await self.client.find_servers()
        if not descriptions:
            engine.pretty_log("No server descriptions returned")
            return
        engine.iterate_server_descriptions(descriptions)

    async def _walk(self, root_token, predicate, label, limit=5000):
        """
        Breadth-first walk from a root node yielding nodes matching predicate.
        Bounded by `limit` visited nodes so a huge address space cannot hang
        the console silently.
        """
        root = resolve_node(self.client, root_token or "objects")
        seen = set()
        queue = [root]
        visited = 0
        found = 0
        skipped = 0
        while queue and visited < limit:
            node = queue.pop(0)
            key = node.nodeid.to_string()
            if key in seen:
                continue
            seen.add(key)
            visited += 1

            # Evaluate the predicate and enumerate children independently, so a
            # read failure on this node cannot suppress traversal into its
            # children (which would silently under-report the whole subtree).
            try:
                matched = await predicate(node)
            except Exception:
                matched = False
                skipped += 1
            if matched:
                found += 1
                try:
                    bname = (await node.read_browse_name()).to_string()
                except Exception:
                    bname = "?"
                engine.pretty_log(
                    f"  {node.nodeid.to_string():<24} {bname}",
                    lvl="success"
                )

            try:
                for child in await node.get_children():
                    if child.nodeid.to_string() not in seen:
                        queue.append(child)
            except Exception:
                skipped += 1
                continue
        if visited >= limit:
            engine.pretty_log(
                f"Stopped after visiting {limit} nodes (limit reached); "
                "narrow the search with a start node.",
                lvl="critical"
            )
        summary = f"{label}: {found} found ({visited} nodes visited"
        summary += f", {skipped} skipped due to read errors)" if skipped else ")"
        engine.pretty_log(summary)

    async def cmd_writable(self, args):
        async def is_writable(node):
            if await node.read_node_class() != ua.NodeClass.Variable:
                return False
            try:
                access = await node.get_user_access_level()
            except Exception:
                return False
            return ua.AccessLevel.CurrentWrite in access

        engine.pretty_log("Searching for writable variable nodes...")
        await self._walk(args[0] if args else None, is_writable,
                         "Writable nodes")

    async def cmd_methods(self, args):
        async def is_method(node):
            return await node.read_node_class() == ua.NodeClass.Method

        engine.pretty_log("Searching for callable methods...")
        await self._walk(args[0] if args else None, is_method, "Methods")

    async def cmd_call(self, args):
        if len(args) < 2:
            engine.pretty_log(
                "Usage: call <object> <method> [args...]", lvl="error"
            )
            return
        parent = resolve_node(self.client, args[0])
        method = resolve_node(self.client, args[1])
        call_args = args[2:]
        coerced = [coerce_call_arg(a) for a in call_args]
        result = await parent.call_method(method, *coerced)
        engine.pretty_log(f"Method result: {result!r}", lvl="success")

    async def cmd_aliases(self, args):
        for alias, nid in NODE_ALIASES.items():
            engine.pretty_log(f"  {alias:<10} -> {nid}")

    # ---- dispatch loop -------------------------------------------------- #

    async def repl(self):
        engine.pretty_log("Type 'help' for commands, 'exit' to quit.")
        handlers = {
            "read": self.cmd_read,
            "write": self.cmd_write,
            "browse": self.cmd_browse,
            "ls": self.cmd_browse,
            "info": self.cmd_info,
            "endpoints": self.cmd_endpoints,
            "servers": self.cmd_servers,
            "writable": self.cmd_writable,
            "methods": self.cmd_methods,
            "call": self.cmd_call,
            "aliases": self.cmd_aliases,
        }
        while True:
            try:
                line = await ainput("opcua> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            parts = line.split()
            cmd, cmd_args = parts[0].lower(), parts[1:]

            if cmd in ("exit", "quit"):
                break
            if cmd in ("help", "menu", "?"):
                print(HELP_TEXT)
                continue

            handler = handlers.get(cmd)
            if handler is None:
                engine.pretty_log(
                    f"Unknown command '{cmd}'. Type 'help'.", lvl="error"
                )
                continue
            try:
                await handler(cmd_args)
            except KeyboardInterrupt:
                print()
                engine.pretty_log("Command aborted", lvl="error")
            except Exception as err:
                engine.pretty_log(f"Command error: {err}", lvl="error")


##############################################################################
#                              Entry points                                  #
##############################################################################

def resolve_url(args):
    """
    Build the target URL from either an explicit --url/-t or the
    hostname/port/path trio.
    """
    if getattr(args, "url", None):
        return args.url
    host = getattr(args, "hostname", "localhost")
    port = getattr(args, "port", 4840)
    path = getattr(args, "path", "/") or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"opc.tcp://{host}:{port}{path}"


async def run_interactive(args):
    """
    Launch the interactive console from a parsed namespace. Any auth field
    left unset is prompted for interactively.
    """
    engine.silence_asyncua_logger()
    url = resolve_url(args)

    # If the caller supplied auth details on the command line, use them as-is;
    # otherwise ask interactively.
    if getattr(args, "authentication", None):
        auth_ns = build_auth_namespace(
            authentication=args.authentication,
            username=getattr(args, "username", "") or "",
            password=getattr(args, "password", "") or "",
            certificate=getattr(args, "certificate", "") or "",
            private_key=getattr(args, "private_key", "") or "",
            mode=getattr(args, "mode", "None") or "None",
            policy=getattr(args, "policy", "None") or "None",
        )
    else:
        try:
            auth_ns = await prompt_for_auth()
        except (EOFError, KeyboardInterrupt):
            engine.pretty_log("Aborted", lvl="error")
            return

    console = OpcuaConsole(url, auth_ns)
    try:
        if not await console.connect():
            return
        await console.repl()
    finally:
        await console.disconnect()
        engine.pretty_log("Disconnected", lvl="success")


def init_standalone_parser():
    parser = argparse.ArgumentParser(
        description="Interactive OPC UA assessment console"
    )
    parser.add_argument("-t", "--url", "--target", dest="url",
                        help="Full target URL (opc.tcp://host:port/path). "
                             "Overrides --hostname/--port/--path.")
    parser.add_argument("--hostname", default="localhost",
                        help="Server hostname (default: localhost)")
    parser.add_argument("--port", type=int, default=4840,
                        help="Server port (default: 4840)")
    parser.add_argument("--path", default="/",
                        help="Server endpoint path (default: /)")
    parser.add_argument("-a", "--authentication",
                        choices=engine.valid_auth_methods,
                        help="Authentication method. If omitted you are "
                             "prompted interactively.")
    parser.add_argument("-u", "--username", default="")
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("-c", "--certificate", default="")
    parser.add_argument("-pk", "--private_key", default="")
    parser.add_argument("-m", "--mode",
                        choices=list(engine.valid_security_modes.keys()),
                        default="None")
    parser.add_argument("-po", "--policy",
                        choices=list(engine.valid_security_policies.keys()),
                        default="None")
    return parser


def main():
    parser = init_standalone_parser()
    args = parser.parse_args()
    asyncio.run(run_interactive(args))


def _enable_windows_ansi():
    """
    On Windows, enabling virtual-terminal processing makes the ANSI colour
    codes used by pretty_log render correctly. The constant empty string is
    not attacker-controllable, so there is no command-injection surface.
    """
    if os.name == "nt":
        os.system("")  # noqa: S605 - constant, Windows ANSI enablement only


if __name__ == "__main__":
    _enable_windows_ansi()
    main()
