#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
opcua_toolkit.py - Unified entry point for the OPC UA assessment toolkit.

One command exposes both approaches to an OPC UA security assessment:

  Non-interactive (scripting / automation):
    hello           Detect OPC UA servers across hosts and ports
    server_config   Gather endpoint, security and access-control information
    read_data       Read node values, optionally browsing a subtree
    write_data      Write a typed value to a node (auto type detection)

  Interactive (hands-on investigation):
    interactive     Open a live console to browse, read, write and call methods

The non-interactive commands are the opcua_scan engine; the interactive
command is the opcua_client console. Both share the same connection,
authentication, security and type-coercion code, so results are consistent.

Examples:
  ./opcua_toolkit.py hello -i 127.0.0.1 -p '4840, 53530'
  ./opcua_toolkit.py server_config -t opc.tcp://127.0.0.1:53530/OPCUA/Sim -nw
  ./opcua_toolkit.py read_data  -t opc.tcp://127.0.0.1:53530/OPCUA/Sim
  ./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:53530/OPCUA/Sim \
        -r 'ns=2;i=2003' -d 42
  ./opcua_toolkit.py interactive -t opc.tcp://127.0.0.1:53530/OPCUA/Sim
"""

import argparse
import asyncio
import os

import opcua_scan as engine
import opcua_client as console


def init_interactive_arg_parser(subparsers):
    """
    Add the `interactive` subcommand. Any auth field left unset is prompted
    for once the console starts.
    """
    parser = subparsers.add_parser(
        "interactive",
        help="Open an interactive OPC UA console (browse/read/write/call)"
    )
    parser.add_argument(
        "-t", "--url", "--target", dest="url",
        help="Full target URL (opc.tcp://host:port/path). Overrides "
             "--hostname/--port/--path."
    )
    parser.add_argument("--hostname", default="localhost",
                        help="Server hostname (default: localhost)")
    parser.add_argument("--port", type=int, default=4840,
                        help="Server port (default: 4840)")
    parser.add_argument("--path", default="/",
                        help="Server endpoint path (default: /)")
    parser.add_argument(
        "-a", "--authentication",
        choices=engine.valid_auth_methods,
        help="Authentication method. If omitted, you are prompted."
    )
    parser.add_argument("-u", "--username", default="",
                        help="Username for Username authentication")
    parser.add_argument("-p", "--password", default="",
                        help="Password for Username authentication")
    parser.add_argument("-c", "--certificate", default="",
                        help="Certificate for auth and/or encryption")
    parser.add_argument("-pk", "--private_key", default="",
                        help="Private key for auth and/or encryption")
    parser.add_argument(
        "-m", "--mode",
        choices=list(engine.valid_security_modes.keys()), default="None",
        help="Channel security mode (default: None)"
    )
    parser.add_argument(
        "-po", "--policy",
        choices=list(engine.valid_security_policies.keys()), default="None",
        help="Channel security policy (default: None)"
    )
    return parser


def build_parser():
    """
    Build the scan engine's parser and graft on the interactive subcommand.
    """
    parser = engine.init_arg_parser()
    parser.prog = "opcua_toolkit"
    parser.description = (
        "OPC UA assessment toolkit - detect servers, inspect their security "
        "and access control, read and write node values, both from the "
        "command line and from an interactive console."
    )
    parser.epilog = (
        "Examples:\n"
        "  ./opcua_toolkit.py hello -i 127.0.0.1 -p '4840, 53530'\n"
        "  ./opcua_toolkit.py server_config -t opc.tcp://127.0.0.1:4840/ -nw\n"
        "  ./opcua_toolkit.py read_data  -t opc.tcp://127.0.0.1:4840/\n"
        "  ./opcua_toolkit.py write_data -t opc.tcp://127.0.0.1:4840/ "
        "-r 'ns=2;i=2' -d 42\n"
        "  ./opcua_toolkit.py interactive -t opc.tcp://127.0.0.1:4840/\n"
    )
    # Locate the existing subparsers action so we can register one more command.
    subparsers_action = next(
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    # Keep subcommand usage lines consistent with the toolkit prog name.
    subparsers_action._prog_prefix = "opcua_toolkit"
    init_interactive_arg_parser(subparsers_action)
    return parser


async def run():
    engine.silence_asyncua_logger()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "interactive":
        await console.run_interactive(args)
        return 0

    status = await engine.dispatch(args)
    # None is treated as success; False signals a handled failure.
    return 0 if status is None or status else 1


def main():
    import sys
    sys.exit(asyncio.run(run()))


if __name__ == "__main__":
    if os.name == "nt":
        os.system("")  # noqa: S605 - constant, Windows ANSI enablement only
    main()
