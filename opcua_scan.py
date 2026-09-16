#!/usr/bin/env python3
# -*- coding: utf-8 -

# pylint: disable=broad-exception-caught, protected-access, global-statement
# pylint: disable=too-many-lines

"""
OPC UA Scanner: Detect OPC UA servers, and retrieve security related
information about them
"""


##############################################################################
#                               Import Section                               #
##############################################################################

import argparse
import logging
import asyncio
import json
import base64
import dataclasses
import os
import os.path
from tabulate import tabulate
from asyncua import ua, Client
from asyncua.common import ua_utils
from asyncua.crypto import security_policies, uacrypto
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

if os.name == "nt":
    os.system("")  # enables ansi escape characters in terminal for Windows


##############################################################################
#                          Global variables section                          #
##############################################################################

application_types = ["SERVER", "CLIENT", "CLIENTANDSERVER", "DISCOVERYSERVER"]
valid_auth_methods = ["Anonymous", "Username", "Certificate", "Issued"]
valid_security_modes = {
    "None": ua.MessageSecurityMode.None_,
    "Sign": ua.MessageSecurityMode.Sign,
    "SignAndEncrypt": ua.MessageSecurityMode.SignAndEncrypt
}
valid_security_policies = {
    "None": None,
    "Basic128Rsa15": security_policies.SecurityPolicyBasic128Rsa15,
    "Basic256": security_policies.SecurityPolicyBasic256,
    "Basic256Sha256": security_policies.SecurityPolicyBasic256Sha256,
    "Aes128Sha256RsaOaep": security_policies.SecurityPolicyAes128Sha256RsaOaep
}
valid_node_attributes = {
    "NodeId": ua.AttributeIds.NodeId,
    "NodeClass": ua.AttributeIds.NodeClass,
    "BrowseName": ua.AttributeIds.BrowseName,
    "DisplayName": ua.AttributeIds.DisplayName,
    "Description": ua.AttributeIds.Description,
    "WriteMask": ua.AttributeIds.WriteMask,
    "UserWriteMask": ua.AttributeIds.UserWriteMask,
    "IsAbstract": ua.AttributeIds.IsAbstract,
    "Symmetric": ua.AttributeIds.Symmetric,
    "InverseName": ua.AttributeIds.InverseName,
    "ContainsNoLoops": ua.AttributeIds.ContainsNoLoops,
    "EventNotifier": ua.AttributeIds.EventNotifier,
    "Value": ua.AttributeIds.Value,
    "DataType": ua.AttributeIds.DataType,
    "ValueRank": ua.AttributeIds.ValueRank,
    "ArrayDimensions": ua.AttributeIds.ArrayDimensions,
    "AccessLevel": ua.AttributeIds.AccessLevel,
    "UserAccessLevel": ua.AttributeIds.UserAccessLevel,
    "MinimumSamplingInterval": ua.AttributeIds.MinimumSamplingInterval,
    "Historizing": ua.AttributeIds.Historizing,
    "Executable": ua.AttributeIds.Executable,
    "UserExecutable": ua.AttributeIds.UserExecutable,
    "DataTypeDefinition": ua.AttributeIds.DataTypeDefinition,
    "RolePermissions": ua.AttributeIds.RolePermissions,
    "UserRolePermissions": ua.AttributeIds.UserRolePermissions,
    "AccessRestrictions": ua.AttributeIds.AccessRestrictions,
    "AccessLevelEx": ua.AttributeIds.AccessLevelEx
}
valid_table_formats = {
    "plain",
    "simple",
    "github",
    "grid",
    "simple_grid",
    "rounded_grid",
    "heavy_grid",
    "mixed_grid",
    "double_grid",
    "fancy_grid",
    "outline",
    "simple_outline",
    "rounded_outline",
    "heavy_outline",
    "mixed_outline",
    "double_outline",
    "fancy_outline",
    "pipe",
    "orgtbl",
    "asciidoc",
    "jira",
    "presto",
    "pretty",
    "psql",
    "rst",
    "mediawiki",
    "moinmoin",
    "youtrack",
    "html",
    "unsafehtml",
    "latex",
    "latex_raw",
    "latex_booktabs",
    "latex_longtable",
    "textile",
    "tsv"
}

MSG_PREFIX = ""

TARGET_COUNTER = 0
DETECTED_SERVER_COUNTER = 0
WRITABLE_NODE_COUNTER = 0
EXECUTABLE_NODE_COUNTER = 0


##############################################################################
#                            Hello script section                            #
##############################################################################

async def run_hello(args):
    """
    Sends an Hello message to all the given hosts on all the given ports.
    """
    pretty_log("Start hello scan...")

    # Parse hosts/ports/names up front. Only this stage can raise a
    # "format" error, so only it is wrapped in the format handler.
    try:
        # Note: we deliberately do not use ipparser here. Its parser reads
        # from stdin whenever stdin is not a TTY and then ignores the -i
        # argument, which makes scans hang or silently find nothing when the
        # tool is scripted or piped. expand_hosts is a self-contained
        # equivalent (single IPs/hostnames, comma lists, dashed IPv4 ranges,
        # CIDR blocks and .txt host files).
        hosts = expand_hosts(args.ip_addresses)
        port_ranges = [port_rng.strip() for port_rng in args.ports.split(",")]

        # Retrieve list of server name to test
        server_names = []
        if os.path.isfile(args.name):
            with open(args.name, "r", encoding="utf-8") as names_file:
                server_names = [
                    name.strip() for name in names_file.readlines()
                ]
        else:
            server_names.append(args.name)
    except Exception as err:
        reset_msg_prefix()
        pretty_log("Invalid hosts or ports format: " + str(err), lvl="error")
        return False

    if not hosts:
        pretty_log(
            f"No valid hosts parsed from '{args.ip_addresses}'", lvl="error"
        )
        return False

    output_object = [] if args.output else False

    for server_name in server_names:
        for host in hosts:
            for port_rng in port_ranges:
                # Handle port range
                if "-" in port_rng:
                    start_port, last_port = port_rng.split("-")
                    port_range = range(int(start_port), int(last_port) + 1)
                # Handle single port
                else:
                    port_range = range(int(port_rng), int(port_rng) + 1)

                for port in port_range:
                    await hello_scan_target(
                        args, host, port, server_name, output_object
                    )

    reset_msg_prefix()
    generate_hello_report(args, TARGET_COUNTER, DETECTED_SERVER_COUNTER)

    # Write in output file if configured (its own handler so a write failure
    # is reported accurately and cannot be mistaken for a parsing error).
    if output_object is not False:
        try:
            with open(args.output, "w", encoding="utf-8") as outfile:
                json.dump(output_object, outfile)
        except OSError as err:
            pretty_log(
                f"Failed to write output file '{args.output}': {err}",
                lvl="error"
            )
            return False

    return DETECTED_SERVER_COUNTER > 0


async def hello_scan_target(args, host, port, server_name, output_object):
    """
    Sends an OPC UA Hello Message to the target
    """
    global MSG_PREFIX, TARGET_COUNTER, DETECTED_SERVER_COUNTER
    MSG_PREFIX = f"{host}:{port}/{server_name} - "

    # Send Hello to target
    connection_str = f"opc.tcp://{host}:{port}/{server_name}"
    client = Client(connection_str, timeout=int(args.timeout) / 1000)
    TARGET_COUNTER += 1

    if await precheck_connection(client):
        DETECTED_SERVER_COUNTER += 1
        pretty_log("Success: OPC UA Server Discovered", lvl="success")
        server_descriptions = await get_server_descriptions(client)
        iterate_server_descriptions(server_descriptions)

        if output_object is not False:
            output_object.append({
                "target": connection_str,
                "known_servers": list(
                    map(dataclasses.asdict, server_descriptions)
                )
            })
    elif args.verbose:
        pretty_log("Failure: no OPC UA server", lvl="error")


def generate_hello_report(args, target_counter, detected_server_counter):
    """
    Displays a summary of the hello scan results
    """

    table = [
        ["Targets scanned", f"{target_counter} target(s) scanned"],
        [
            "Servers detected",
            f"{detected_server_counter} OPC UA server(s) detected"
        ]
    ]
    print("\n")
    print(
        tabulate(table, tablefmt=args.table_format, headers=["", "Results"])
    )


##############################################################################
#                        read_data script section                            #
##############################################################################

async def read_data(args):
    """
    Starts reading data
    """
    # Init
    targets = build_targets(args)
    targets_report_object = []
    if not targets:
        pretty_log("No valid targets to read from", lvl="error")
        return False

    responded = 0
    # Start scan (multiple targets are supported, e.g. from a hello_output.json)
    for target in targets:
        client = Client(target)
        global MSG_PREFIX
        MSG_PREFIX = f"{target} - "

        if await precheck_connection(client):
            responded += 1
            print("\n")
            pretty_log(
                "Valid OPC UA response, starting analysis",
                lvl="success"
            )

            target_report = {"target": target, "endpoints": [], "tree": []}
            targets_report_object.append(target_report)

            endpoints = await get_endpoints(client)
            try:
                iterate_endpoints(endpoints, target_report)
            except Exception as err:
                pretty_log(
                    f"Could not process endpoints: {err}", lvl="error"
                )

            if await check_authentication(client, args, target_report):
                try:
                    await read_server_nodes(client, args, target_report)
                except Exception:
                    continue

        else:
            print("\n")
            pretty_log("No OPC UA response, stop scan", lvl="error")

    # Write the scan results in the verbose file
    if args.output_verbose:
        try:
            with open(args.output_verbose, "w", encoding="utf-8") as outfile:
                json.dump(targets_report_object, outfile)
        except OSError as err:
            pretty_log(
                f"Failed to write output file '{args.output_verbose}': {err}",
                lvl="error"
            )

    return responded > 0

##############################################################################
#                        write_data script section                           #
#              Only works in a very limited way for the workshop             #
##############################################################################

async def write_data(args):
    """
    Starts writing data
    """
    # Init
    targets = build_targets(args)
    targets_report_object = []
    if not targets:
        pretty_log("No valid target to write to", lvl="error")
        return False
    # Writing fans out to every target, so refuse more than one: the same
    # physical server can appear under several discovery URLs and we must not
    # write the same value repeatedly to a live process.
    if len(targets) > 1:
        pretty_log(
            "Only one target is supported for write_data (got "
            f"{len(targets)}); pass a single -t URL",
            lvl="error"
        )
        return False

    wrote = False
    # Start scan
    for target in targets:
        client = Client(target)
        global MSG_PREFIX
        MSG_PREFIX = f"{target} - "

        if await precheck_connection(client):
            print("\n")
            pretty_log(
                "Valid OPC UA response, starting analysis",
                lvl="success"
            )

            target_report = {"target": target, "endpoints": [], "tree": []}
            targets_report_object.append(target_report)

            endpoints = await get_endpoints(client)
            try:
                iterate_endpoints(endpoints, target_report)
            except Exception as err:
                pretty_log(
                    f"Could not process endpoints: {err}", lvl="error"
                )

            if await check_authentication(client, args, target_report):
                try:
                    await write_server_nodes(client, args)
                    wrote = True
                except Exception:
                    continue

        else:
            print("\n")
            pretty_log("No OPC UA response, stop scan", lvl="error")

    return wrote


##############################################################################
#                        Server_config script section                        #
#                                                                            #
##############################################################################

async def run_server_config(args):
    """
    Starts the server_config scan
    """
    # Init
    targets = build_targets(args)
    targets_report_object = []

    # Start scan
    for target in targets:
        client = Client(target)
        global MSG_PREFIX
        MSG_PREFIX = f"{target} - "

        if await precheck_connection(client):
            print("\n")
            pretty_log(
                "Valid OPC UA response, starting analysis",
                lvl="success"
            )

            target_report = {"target": target, "endpoints": [], "tree": []}
            targets_report_object.append(target_report)

            endpoints = await get_endpoints(client)
            try:
                iterate_endpoints(endpoints, target_report)
            except Exception as err:
                pretty_log(
                    f"Could not process endpoints: {err}", lvl="error"
                )

            if args.servers:
                # Ask for all known servers
                try:
                    server_descriptions = await get_server_descriptions(client)
                    pretty_log("Found Servers:")
                    iterate_server_descriptions(server_descriptions)
                except Exception as err:
                    pretty_log(
                        f"Could not list known servers: {err}", lvl="error"
                    )

            if await check_authentication(client, args, target_report):
                if (
                    args.nodes_writable or
                    args.nodes_executable or
                    args.node_attributes
                ):
                    try:
                        await get_server_nodes(client, args, target_report)
                    except Exception:
                        continue

        else:
            print("\n")
            pretty_log("No OPC UA response, stop scan", lvl="error")

    generate_config_report(
        args,
        WRITABLE_NODE_COUNTER,
        EXECUTABLE_NODE_COUNTER,
        targets_report_object
    )

    # Write the scan results in the verbose file
    if args.output_verbose:
        try:
            with open(args.output_verbose, "w", encoding="utf-8") as outfile:
                json.dump(targets_report_object, outfile)
        except OSError as err:
            pretty_log(
                f"Failed to write output file '{args.output_verbose}': {err}",
                lvl="error"
            )

    # At least one target responded to the precheck.
    return len(targets_report_object) > 0


def generate_config_report(
    args,
    writable_node_counter,
    executable_node_counter,
    targets_report_object
):
    """
    Displays a summary of the server_config scan results
    """
    # Distinguish "measured and secure" from "could not measure". Targets are
    # only added to targets_report_object when they respond to the Hello
    # precheck, and their endpoints list is empty when enumeration failed. In
    # either case we must NOT print a green "hardened" verdict.
    responded = len(targets_report_object)
    total_endpoints = sum(
        len(target["endpoints"]) for target in targets_report_object
    )

    if responded == 0:
        table = [
            ["Targets scanned", "0 target(s) responded"],
            [
                "Security posture",
                "\033[91m\033[1mNOT DETERMINED\033[0m "
                "(no target reachable)"
            ],
        ]
        print("\n")
        print(
            tabulate(
                table, tablefmt=args.table_format, headers=["", "Results"]
            )
        )
        return

    unknown_msg = (
        "\033[93m\033[1mUNKNOWN\033[0m (endpoints not enumerated)"
    )

    # Allowed anonymous connection
    anonymous_connection_allowed_counter = 0
    for target in targets_report_object:
        next_target = False
        for endpoint in target["endpoints"]:
            if next_target:
                break

            for accepted_token in endpoint["UserIdentityTokens"]:
                if accepted_token["TokenType"] == ua.UserTokenType.Anonymous:
                    anonymous_connection_allowed_counter += 1
                    next_target = True
                    break

    anonymous_connection_msg = ""
    if total_endpoints == 0:
        anonymous_connection_msg = unknown_msg
    elif anonymous_connection_allowed_counter > 0:
        anonymous_connection_msg += "\033[93m\033[1m" + "ALLOWED" + "\033[0m"
        anonymous_connection_msg += (
            f" (for {anonymous_connection_allowed_counter} targets)"
        )
    else:
        anonymous_connection_msg += (
            "\033[92m\033[1m" + "NOT ALLOWED" + "\033[0m"
        )

    # Security mode
    none_counter, sign_and_encrypt_only = 0, True
    for target in targets_report_object:
        for endpoint in target["endpoints"]:
            if (
                endpoint["SecurityMode"] == 1 and
                endpoint["EndpointUrl"].startswith("opc.tcp")
            ):
                none_counter += 1

            if sign_and_encrypt_only and endpoint["SecurityMode"] != 3:
                sign_and_encrypt_only = False

    security_mode_msg = ""
    if total_endpoints == 0:
        security_mode_msg = unknown_msg
    elif none_counter > 0:
        security_mode_msg += (
            "Mode None " + "\033[93m\033[1m" + "ALLOWED" + "\033[0m"
        )
        security_mode_msg += f" (for {none_counter} targets)"
    else:
        security_mode_msg += (
            "Mode None " + "\033[92m\033[1m" + "NOT ALLOWED" + "\033[0m"
        )
        if sign_and_encrypt_only:
            security_mode_msg += " (SignAndEncrypt only)"
        else:
            security_mode_msg += " (Sign or SignAndEncrypt)"

    # Authentication
    successful_auth_counter = 0
    for target in targets_report_object:
        if target["authentication"] == "Successful":
            successful_auth_counter += 1
    auth_msg = f" {successful_auth_counter} successful authentication(s)"

    table = [
        ["Targets scanned", f"{len(targets_report_object)} target(s)"],
        ["Anonymous connection", anonymous_connection_msg],
        ["Security mode", security_mode_msg],
        ["Authentication", auth_msg]
    ]

    # Nodes
    if args.nodes_writable:
        writable_nodes_msg = f"{writable_node_counter} nodes can be modified"
        table.append(["Writable nodes", writable_nodes_msg])

    if args.nodes_executable:
        editable_nodes_msg = (
            f"{executable_node_counter} methods can be executed"
        )
        table.append(["Executable methods", editable_nodes_msg])

    print("\n")
    print(
        tabulate(table, tablefmt=args.table_format, headers=["", "Results"])
    )

def generate_reading_report(
    args,
    targets_report_object
):
    """
    Displays a summary of the read_data scan results
    """

    table = []

    # Nodes & values
    for node in targets_report_object:
        table.append([node["NodeId"], node["BrowseName"], node["Value"]])

    print("\n")
    print(
        tabulate(table, tablefmt='outline', headers=["Node", "Name", "Value"])
    )



MAX_EXPANDED_HOSTS = 65536


def expand_hosts(spec):
    """
    Expand an IP/host specification into a list of hosts, without relying on
    ipparser (whose stdin handling ignores the argument when stdin is not a
    TTY). Supports:
      - single IPs and hostnames,
      - comma-separated lists,
      - dashed IPv4 ranges (a.b.c.d-e),
      - CIDR blocks (bounded to avoid materialising huge/IPv6 ranges),
      - a path to a .txt file with one specification per line.
    Invalid octets and reversed ranges are reported and skipped rather than
    silently mis-expanded. Unknown tokens are passed through unchanged so
    hostnames still work.
    """
    import re
    import ipaddress

    def valid_octet(value):
        return 0 <= value <= 255

    hosts = []

    # A .txt file expands to one specification per line (recursively).
    spec_str = str(spec).strip()
    if spec_str.lower().endswith(".txt") and os.path.isfile(spec_str):
        with open(spec_str, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.extend(expand_hosts(line))
    else:
        for token in spec_str.split(","):
            token = token.strip()
            if not token:
                continue

            # Dashed IPv4 range, e.g. 10.0.0.1-20
            range_match = re.match(
                r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})$", token
            )
            if range_match:
                o1, o2, o3, start, end = (int(g) for g in range_match.groups())
                if not all(valid_octet(o) for o in (o1, o2, o3, start, end)):
                    pretty_log(
                        f"Ignoring range with octet > 255: '{token}'",
                        lvl="critical"
                    )
                    continue
                if start > end:
                    pretty_log(
                        f"Ignoring reversed range '{token}' "
                        f"(start {start} > end {end})",
                        lvl="critical"
                    )
                    continue
                for last in range(start, end + 1):
                    hosts.append(f"{o1}.{o2}.{o3}.{last}")
                continue

            # CIDR block, e.g. 192.168.0.0/30
            if "/" in token:
                try:
                    network = ipaddress.ip_network(token, strict=False)
                except ValueError:
                    hosts.append(token)
                    continue
                if network.version == 6:
                    pretty_log(
                        f"Ignoring IPv6 CIDR '{token}' (IPv6 targets are "
                        "not supported)",
                        lvl="critical"
                    )
                    continue
                if network.num_addresses > MAX_EXPANDED_HOSTS:
                    pretty_log(
                        f"Ignoring CIDR '{token}': {network.num_addresses} "
                        f"addresses exceeds the {MAX_EXPANDED_HOSTS} cap",
                        lvl="critical"
                    )
                    continue
                for ip in network:
                    hosts.append(str(ip))
                continue

            hosts.append(token)

    # De-duplicate while preserving order.
    seen = set()
    ordered = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            ordered.append(host)
    return ordered


def build_targets(args):
    """
    Returns a list of URL to scan from the args input
    """
    if os.path.isfile(args.targets):
        targets = []
        try:
            with open(args.targets, "r", encoding="utf-8") as targets_file:
                file_data = json.load(targets_file)
            for detected_server in file_data:
                for known_server in detected_server.get("known_servers", []):
                    for discovery_url in known_server.get("DiscoveryUrls", []):
                        # HTTPS not supported yet
                        if (
                            isinstance(discovery_url, str)
                            and discovery_url.startswith("opc.tcp")
                            and discovery_url not in targets
                        ):
                            targets.append(discovery_url)
        except json.JSONDecodeError as err:
            pretty_log(
                f"Invalid targets file '{args.targets}': not valid JSON "
                f"({err})",
                lvl="error"
            )
            return []
        except (TypeError, AttributeError) as err:
            pretty_log(
                f"Unexpected structure in targets file '{args.targets}': "
                f"expected the output of the hello command ({err})",
                lvl="error"
            )
            return []
    else:
        targets = [
            target.strip()
            for target in args.targets.split(",")
            if target.strip()
        ]
    return targets


async def check_authentication(client, args, target_report):
    """
    Tries to make an authentication to an OPC UA server.
    Returns True if it is successful, False otherwise.
    """
    target_report["authentication"] = "Failed"
    if await setup_client_for_authentication(client, args):
        try:
            await client.connect()
            await client.disconnect()
            pretty_log(
                f"Successful {args.authentication} authentication",
                lvl="success"
            )
            target_report["authentication"] = "Successful"
            return True

        except asyncio.exceptions.TimeoutError:
            pretty_log(
                f"{args.authentication} authentication failed : Timeout error"
                ", no response from the server",
                lvl="error"
            )
            return False
        except Exception as err:
            pretty_log(
                f"{args.authentication} authentication failed : {err}",
                lvl="error"
            )
            return False
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    else:
        pretty_log("Client setup failed", lvl="error")
        return False


async def read_server_nodes(client, args, target_report):
    """
    Tries to retrieves server nodes
    """
    try:
        await client.connect()
        root = (
            client.get_root_node() if not args.root_node
            else client.get_node(args.root_node)
        )

        # Iterate over all nodes and check permissions
        pretty_log("List of nodes and values:")
        await read_node_values(args, root, target_report["tree"])
        await client.disconnect()

    except Exception as err:
        pretty_log(f"Could not obtain information: {err}", lvl="error")
        try:
            await client.disconnect()
        except Exception:
            pass
        raise err

INTEGER_VARIANT_TYPES = (
    ua.VariantType.Int16, ua.VariantType.Int32, ua.VariantType.Int64,
    ua.VariantType.UInt16, ua.VariantType.UInt32, ua.VariantType.UInt64,
    ua.VariantType.Byte, ua.VariantType.SByte,
)
FLOAT_VARIANT_TYPES = (ua.VariantType.Float, ua.VariantType.Double)


def cast_to_variant(raw, variant_type):
    """
    Cast a raw string (or already-typed value) to the Python type expected by
    the given ua.VariantType, so ua.Variant(value, variant_type) can actually
    be serialized. Mirrors the coercion used by the interactive client and the
    standalone writer script.

    Raises ValueError for a VariantType we cannot safely coerce a string into,
    rather than returning a raw string that asyncua would fail to serialize at
    write time (which previously surfaced as a confusing "Error in writing to
    node" and made those node types look non-writable).
    """
    if variant_type in INTEGER_VARIANT_TYPES:
        return int(raw)
    if variant_type in FLOAT_VARIANT_TYPES:
        return float(raw)
    if variant_type == ua.VariantType.Boolean:
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    if variant_type == ua.VariantType.String:
        return str(raw)

    if variant_type == ua.VariantType.ByteString:
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        text = str(raw).strip()
        # Accept hex ("0x..." or bare hex) or base64; fall back to UTF-8 bytes.
        try:
            if text.lower().startswith("0x"):
                return bytes.fromhex(text[2:])
            return bytes.fromhex(text)
        except ValueError:
            pass
        try:
            return base64.b64decode(text, validate=True)
        except Exception:
            return text.encode("utf-8")

    if variant_type == ua.VariantType.DateTime:
        import datetime
        if isinstance(raw, datetime.datetime):
            return raw
        text = str(raw).strip()
        try:
            parsed = datetime.datetime.fromisoformat(text)
        except ValueError:
            # Accept a Unix epoch (seconds) as a fallback.
            parsed = datetime.datetime.fromtimestamp(
                float(text), tz=datetime.timezone.utc
            )
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed

    if variant_type == ua.VariantType.Guid:
        import uuid
        if isinstance(raw, uuid.UUID):
            return raw
        return uuid.UUID(str(raw).strip())

    raise ValueError(
        f"Writing VariantType {variant_type.name} is not supported. Supported "
        "types: Boolean, the signed/unsigned integers, Float, Double, String, "
        "ByteString, DateTime and Guid."
    )


async def resolve_variant_type(node, dtype_override=None):
    """
    Determine the target ua.VariantType for a node.
    dtype_override is a VariantType name (e.g. 'UInt16', 'Float', 'String') and
    takes precedence. Otherwise the node's declared data type is used, falling
    back to the VariantType of its current value.
    """
    if dtype_override:
        variant_type = getattr(ua.VariantType, dtype_override, None)
        if variant_type is None:
            valid = [m for m in dir(ua.VariantType) if not m.startswith("_")]
            raise ValueError(
                f"Unsupported datatype '{dtype_override}'. Valid names: {valid}"
            )
        return variant_type

    try:
        return await node.read_data_type_as_variant_type()
    except Exception:
        try:
            dv = await node.read_data_value()
            if dv.Value.VariantType is not None:
                return dv.Value.VariantType
        except Exception:
            pass
        raise ValueError(
            "Could not determine the node data type. Pass -dt/--dtype to set it "
            "explicitly (e.g. -dt UInt16)."
        )


async def coerce_value_for_node(node, raw, dtype_override=None):
    """
    Resolve a node's VariantType and coerce a raw value to it.
    Returns (python_value, ua.VariantType).
    """
    variant_type = await resolve_variant_type(node, dtype_override)
    return cast_to_variant(raw, variant_type), variant_type


def values_equivalent(written, read_back):
    """
    Compare a written value against the value read back from the server.
    Floats are compared with a tolerance because 32-bit Float nodes round the
    value, which would make a strict equality check report a false mismatch.
    """
    if isinstance(written, float) or isinstance(read_back, float):
        try:
            import math
            return math.isclose(
                float(written), float(read_back), rel_tol=1e-6, abs_tol=1e-9
            )
        except (TypeError, ValueError):
            return written == read_back
    return written == read_back


async def write_server_nodes(client, args):
    """
    Writes a value to a single node.

    The target VariantType is auto-detected from the node (its declared data
    type, or the type of its current value) so any scalar type is supported:
    Boolean, the signed/unsigned integers, Float/Double and String. Pass
    -dt/--dtype to force a specific type. The write is verified by reading the
    value back.
    """
    try:
        await client.connect()
        supplied_node = client.get_node(args.root_node)
        # Read current value for display (best effort)
        value = "BadAttributeIdInvalid"
        try:
            value = ua_utils.val_to_string(
                await supplied_node.read_value(), truncate=True
            )
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            value = str(err)
    except Exception as err:
        pretty_log(f"Could not obtain information: {err}", lvl="error")
        try:
            await client.disconnect()
        except Exception:
            pass
        raise err

    pretty_log(
        f"Previous value at address "
        f"{supplied_node.nodeid.to_string()}: "
        f"""\033[92m\033[1m{value}\033[0m"""
    )

    # Determine the value and its VariantType.
    try:
        data_to_be_written, variant_type = await coerce_value_for_node(
            supplied_node, args.data, args.dtype
        )
    except Exception as err:
        pretty_log(f"Could not prepare value to write: {err}", lvl="error")
        try:
            await client.disconnect()
        except Exception:
            pass
        return

    pretty_log(
        f"Writing value \033[92m\033[1m{data_to_be_written!r}\033[0m "
        f"as \033[92m\033[1m{variant_type.name}\033[0m"
    )

    try:
        dv = ua.DataValue(ua.Variant(data_to_be_written, variant_type))
        await supplied_node.set_value(dv)
        pretty_log(
            f"Successful write of data \033[92m\033[1m{data_to_be_written!r}"
            f"\033[0m at address \033[92m\033[1m{supplied_node}\033[0m",
            lvl="success"
        )

        # Verify by reading the value back
        try:
            new_value = await supplied_node.read_value()
            if values_equivalent(data_to_be_written, new_value):
                pretty_log(
                    f"Verified: node value is now "
                    f"\033[92m\033[1m{new_value!r}\033[0m",
                    lvl="success"
                )
            else:
                pretty_log(
                    f"Verification mismatch: expected {data_to_be_written!r}, "
                    f"read back {new_value!r}",
                    lvl="critical"
                )
        except Exception as err:
            pretty_log(f"Could not verify write: {err}", lvl="critical")

    except Exception as err:
        pretty_log(f"Error in writing to node: {err}", lvl="error")
        try:
            await client.disconnect()
        except Exception:
            pass
        raise err

    await client.disconnect()


async def get_server_nodes(client, args, target_report):
    """
    Tries to retrieves server nodes
    """
    try:
        await client.connect()
        root = (
            client.get_root_node() if not args.root_node
            else client.get_node(args.root_node)
        )

        # Report pruned subtrees so the scope of the scan is explicit
        if getattr(args, "excluded_nodes", None):
            skipped = ", ".join(
                sorted(node.to_string() for node in args.excluded_nodes)
            )
            pretty_log(f"Skipping excluded subtree(s): {skipped}")
        elif not args.root_node:
            pretty_log(
                "Traversing the full address space from the root node. This "
                "can take several minutes; use -st to skip the standard "
                "Server/Types/Views subtrees, or -r to pick a start node.",
                lvl="critical"
            )

        # Iterate over all nodes and check permissions
        pretty_log("Interesting Nodes:")
        await traverse_tree(args, root, target_report["tree"])
        await client.disconnect()

    except Exception as err:
        pretty_log(f"Could not obtain information: {err}", lvl="error")
        try:
            await client.disconnect()
        except Exception:
            pass
        raise err


async def setup_client_for_authentication(client, args):
    """
    Configure the client for the authentication and the encryption of the
    channel
    """
    certpath, keypath = args.certificate, args.private_key
    mode, policy = args.mode, args.policy

    if certpath != "" and not os.path.isfile(certpath):
        pretty_log("Certificate not found", lvl="error")
        return False

    if keypath != "" and not os.path.isfile(keypath):
        pretty_log("Key not found", lvl="error")
        return False

    if args.authentication == valid_auth_methods[1]:  # Username
        client.set_user(args.username)
        client.set_password(args.password)

    elif args.authentication == valid_auth_methods[2]:  # Certificate
        # Loading (wrong format / unreadable) and the SAN-URI extraction can
        # both raise; a failure here must not abort the whole scan.
        try:
            await client.load_client_certificate(certpath)
            await client.load_private_key(keypath)
        except Exception as err:
            pretty_log(
                f"Failed to load certificate/private key: {err}",
                lvl="error"
            )
            return False
        try:
            set_application_uri_from_cert(client, client.user_certificate)
        except Exception as err:
            pretty_log(
                "Failed to set application URI from certificate "
                f"(no usable SubjectAltName URI?): {err}",
                lvl="error"
            )
            return False

    if mode != "None":
        # Check policy if mode is not None
        if policy == "None":
            pretty_log(
                "Security mode other than 'None' is used thus security policy"
                " needs to be one of the following: "
                f"{list(valid_security_policies.keys())[1:]}",
                lvl="error"
            )
            return False

        security_policy = valid_security_policies[policy]
        security_mode = valid_security_modes[mode]

        try:
            await client.set_security(
                security_policy, certpath, keypath, None, None, security_mode
            )
            cert = uacrypto.x509_from_der(
                client.security_policy.host_certificate
            )
            set_application_uri_from_cert(client, cert)
        except Exception as err:
            pretty_log(
                f"Failed to set security mode and policy: {err}",
                lvl="error"
            )
            return False

    return True


def set_application_uri_from_cert(client, cert):
    """
    The application URI provided by the client should match the subject
    name extension of the certificate. This set up the client accordingly.
    """
    alt_name_extension = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    client.application_uri = alt_name_extension.value.get_values_for_type(
        x509.UniformResourceIdentifier
    )[0]


def iterate_endpoints(endpoints, target_report):
    """
    Iterates all endpoints and logs relevant information
    """
    pretty_log("Available Endpoints:")

    for endpoint in endpoints:
        # URL
        pretty_log("-" * 40)
        pretty_log(f"Endpoint: {endpoint.EndpointUrl}")

        # Security mode
        if endpoint.SecurityMode == ua.MessageSecurityMode.None_:
            pretty_log(
                f"Security mode: {str(endpoint.SecurityMode)[20:]}",
                lvl="critical"
            )
        else:
            pretty_log(
                f"Security mode: {str(endpoint.SecurityMode)[20:]} "
                f"with {(endpoint.SecurityPolicyUri or '')[43:]}"
            )

        # Supported authentication
        supported_authentication = []
        anonymous_accepted = False
        for token in endpoint.UserIdentityTokens:
            if token.TokenType not in supported_authentication:
                supported_authentication.append(token.TokenType)
                if token.TokenType == ua.UserTokenType.Anonymous:
                    anonymous_accepted = True

        msg = "Authentication type accepted: "
        for token_type in supported_authentication:
            msg += str(token_type)[14:] + ", "
        pretty_log(msg[:-2], lvl="critical" if anonymous_accepted else "")

        # Convert certificate in base64 (easier to read in the output file)
        if target_report:
            # asyncua >=2.0 returns None (not b"") for endpoints with no
            # certificate, e.g. SecurityMode None; b64encode(None) raises.
            endpoint.ServerCertificate = base64.b64encode(
                endpoint.ServerCertificate or b""
            ).decode("utf-8")
            target_report["endpoints"].append(dataclasses.asdict(endpoint))

    pretty_log("-" * 40)


# Standard OPC UA subtrees that are large and rarely relevant for
# pen-testing. Traversing Server (i=2253) alone accounts for the vast
# majority of node reads on a server with a small application address space.
STANDARD_SKIP_NODES = {
    "i=2253": "Server",
    "i=86": "Types",
    "i=87": "Views",
}


def build_exclusion_set(args):
    """
    Builds the set of NodeIds whose subtrees are skipped during traversal,
    from --exclude-nodes and --skip-standard.

    Accepts bare numeric ids ("2253"), short form ("i=2253") and fully
    qualified form ("ns=0;i=2253"): all are normalised to ua.NodeId so that
    comparison is independent of the spelling used on the command line.
    """
    raw = list(getattr(args, "exclude_nodes", None) or [])
    if getattr(args, "skip_standard", False):
        raw.extend(STANDARD_SKIP_NODES.keys())

    excluded = set()
    for item in raw:
        item = str(item).strip()
        if not item:
            continue
        # Allow "-xs 2253" as shorthand for "-xs i=2253"
        if item.isdigit():
            item = f"i={item}"
        try:
            excluded.add(ua.NodeId.from_string(item))
        except Exception as err:
            pretty_log(
                f"Warning: ignoring invalid NodeId in exclusion list "
                f"'{item}': {err}",
                lvl="critical"
            )
    return excluded


async def traverse_tree(args, root, targets_report_object_tree):
    """
    Recursively iterates all nodes in subtree from given root and logs
    relevant information
    """
    # Skip excluded subtrees entirely (see --exclude-nodes / --skip-standard).
    # Returning here prunes the whole branch: no attribute reads, no recursion.
    if root.nodeid in getattr(args, "excluded_nodes", ()):
        return

    # Init default attributes
    parent_node = {
        "NodeId": "BadNodeIdUnknown",
        "NodeClass": "BadNodeIdUnknown",
        "BrowseName": "BadNodeIdUnknown",
        "Value": "BadAttributeIdInvalid",
        "UserRolePermissions": "BadAttributeIdInvalid",
    }

    # Handle additional attributes configured
    for attr in args.node_attributes:
        try:
            parent_node[attr] = str(
                await root.read_attribute(valid_node_attributes[attr])
            )
        except Exception as err:
            parent_node[attr] = str(err)

    targets_report_object_tree.append(parent_node)

    # Retrieve default attributes
    try:
        parent_node["NodeId"] = root.nodeid.to_string()
        browse_name = await root.read_browse_name()
        parent_node["BrowseName"] = browse_name.to_string()
        node_class = int_to_node_class(await root.read_node_class())
        parent_node["NodeClass"] = node_class.name

        # Value
        try:
            parent_node["Value"] = ua_utils.val_to_string(
                await root.read_value(), truncate=True
            )
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            parent_node["Value"] = str(err)

        # UserRolePermissions
        try:
            user_role_permissions = await root.read_attribute(
                ua.AttributeIds.UserRolePermissions
            )
            parent_node["UserRolePermissions"] = (
                user_role_permissions.Value.Value
            )
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            parent_node["UserRolePermissions"] = str(err)

        # UserWriteMask
        try:
            user_write_mask = await root.read_attribute(
                ua.AttributeIds.UserWriteMask
            )
            parent_node["UserWriteMask"] = [
                mask.name for mask in ua.WriteMask.parse_bitfield(
                    user_write_mask.Value.Value
                )
            ]
        except ua.uaerrors._auto.BadAttributeIdInvalid:
            pass
        except Exception as err:
            parent_node["UserWriteMask"] = str(err)

        # Check if the node is relevant to print and retrieve other attributes
        relevant = False
        if node_class == ua.NodeClass.Variable:
            # UserAccessLevel
            try:
                user_access_level = await root.get_user_access_level()
                if args.nodes_writable:
                    # CurrentWrite only, matching the interactive console and
                    # the "can be modified" label. HistoryWrite is a different
                    # capability and would over-report modifiable nodes.
                    if ua.AccessLevel.CurrentWrite in user_access_level:
                        relevant = True

                parent_node["UserAccessLevel"] = [
                    x.name for x in user_access_level
                ]
            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                parent_node["UserAccessLevel"] = str(err)

        elif node_class == ua.NodeClass.Method:
            # UserExecutable
            try:
                user_executable = (
                    await root.read_attribute(ua.AttributeIds.UserExecutable)
                ).Value.Value
                if args.nodes_executable:
                    relevant = user_executable
                parent_node["UserExecutable"] = user_executable
            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                parent_node["UserExecutable"] = str(err)

        # Display node if relevant
        if relevant:
            global WRITABLE_NODE_COUNTER, EXECUTABLE_NODE_COUNTER
            pretty_log(
                f"Name: {browse_name.to_string()} - "
                f"Id: {root.nodeid.to_string()}"
            )
            if args.nodes_writable and node_class == ua.NodeClass.Variable:
                WRITABLE_NODE_COUNTER += 1
                pretty_log(str([x.name for x in user_access_level]))
            if args.nodes_executable and node_class == ua.NodeClass.Method:
                EXECUTABLE_NODE_COUNTER += 1
                pretty_log("UserExecutable: True")

        parent_node["children"] = []
        children = await root.get_children()
        for child in children:
            await traverse_tree(args, child, parent_node["children"])

    except ua.uaerrors._auto.BadNodeIdUnknown:
        pass

async def read_node_values(args, root, targets_report_object_tree):
    """
   Get all nodes in subtree from given root and logs
    relevant information
    """
    if(args.single):
        child_nodes = []
        child_nodes.append(root)
    else:
        child_nodes = await root.get_children()
    for child_node in child_nodes:

        # Init default attributes
        node = {
            "NodeId": "BadNodeIdUnknown",
            "NodeClass": "BadNodeIdUnknown",
            "BrowseName": "BadNodeIdUnknown",
            "Value": "BadAttributeIdInvalid",
            "UserRolePermissions": "BadAttributeIdInvalid",
        }

        # Retrieve default attributes
        try:
            node["NodeId"] = child_node.nodeid.to_string()
            browse_name = await child_node.read_browse_name()
            node["BrowseName"] = browse_name.to_string()
            node_class = int_to_node_class(await child_node.read_node_class())
            node["NodeClass"] = node_class.name

            # Description, not working as expected
            #desc = await child_node.read_attribute(ua.AttributeIds.Description)

            # Value
            try:
                node["Value"] = ua_utils.val_to_string(
                    await child_node.read_value(), truncate=True
                )

            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                node["Value"] = str(err)
            #print(node)

            # UserRolePermissions
            try:
                user_role_permissions = await child_node.read_attribute(
                    ua.AttributeIds.UserRolePermissions
                )
                node["UserRolePermissions"] = (
                    user_role_permissions.Value.Value
                )
            except ua.uaerrors._auto.BadAttributeIdInvalid:
                pass
            except Exception as err:
                node["UserRolePermissions"] = str(err)

            # Display nodes
            pretty_log(
                f"Name: {browse_name.to_string()} - "
                f"Id: {child_node.nodeid.to_string()} - "
                f"""Value: \033[92m\033[1m{node["Value"]}\033[0m"""
            )

            #print(node)


        except ua.uaerrors._auto.BadNodeIdUnknown:
            pass

        targets_report_object_tree.append(node)

    generate_reading_report(
        args,
        targets_report_object_tree
    )


##############################################################################
#                                Main section                                #
##############################################################################

def silence_asyncua_logger():
    """
    Disable the noisy asyncua logger so tool output stays readable.
    """
    logging.getLogger("asyncua").addHandler(logging.NullHandler())
    logging.getLogger("asyncua").propagate = False


async def dispatch(args):
    """
    Run the scan command described by a parsed argparse namespace.
    Shared by this module's main() and by the unified opcua_toolkit entry
    point, so both expose identical non-interactive behaviour.

    Returns True on success (target(s) reached / value written), False on a
    handled failure, so callers can map it to a process exit status.
    """
    if args.command == "hello":
        return await run_hello(args)

    elif args.command == "read_data":

        if args.root_node:
            # Converts root_id to int if possible
            try:
                root_id = int(args.root_node)
                args.root_node = root_id
            except Exception:
                pass

        return await read_data(args)

    elif args.command == "write_data":

        if args.root_node:
            # Converts root_id to int if possible
            try:
                root_id = int(args.root_node)
                args.root_node = root_id
            except Exception:
                pass

        return await write_data(args)

    elif args.command == "server_config":
        # Handle warning if additional node attributes are badly configured
        if args.node_attributes:
            if not args.output_verbose:
                pretty_log(
                    "Warning: No output file configured, the additional "
                    "targeted node attributes will not be retrieved",
                    lvl="critical"
                )
            else:
                old_attrs = args.node_attributes
                args.node_attributes = [
                    attr for attr in old_attrs if attr in valid_node_attributes
                ]
                for attr in old_attrs:
                    if attr not in args.node_attributes:
                        pretty_log(
                            f"Warning: The attribute {attr} is not valid and "
                            "thus, ignored.",
                            lvl="critical"
                        )

        if args.root_node:
            # Converts root_id to int if possible
            try:
                root_id = int(args.root_node)
                args.root_node = root_id
            except Exception:
                pass

        # Resolve the exclusion list once; traverse_tree reads it per node
        args.excluded_nodes = build_exclusion_set(args)

        return await run_server_config(args)

    return None


async def main():
    """
    opcua_scan standalone entry point (non-interactive commands only).
    """
    silence_asyncua_logger()
    parser = init_arg_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 2
    status = await dispatch(args)
    # None (e.g. unknown command path) is treated as success; False -> failure.
    return 0 if status is None or status else 1


def init_arg_parser():
    """
    Init opcua_scan argparser
    """
    parser = argparse.ArgumentParser(
        prog="opcua_scan",
        description="Scan OPC UA servers",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "./opcua_scan.py hello -h\n"
            "./opcua_scan.py hello -i 127.0.0.1\n"
            "./opcua_scan.py hello -i 127.0.0.1 -p '5060, 53530' -o "
            "hello_output.json\n"
            "./opcua_scan.py server_config -t hello_output.json\n"
            "./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:53530"
            "/OPCUA/SimulationServer' -a Username -u user -p pass -nw\n"
            "./opcua_scan.py server_config -t 'opc.tcp://127.0.0.1:4840"
            "/ServerName' -nw -st\n"
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    # Creating the parser for the "hello" command
    init_hello_arg_parser(subparsers)

    # Creating the parser for the "server_config" command
    init_server_config_arg_parser(subparsers)

    # Creating the parser for the "read_data" command
    init_read_data_arg_parser(subparsers)

    # Creating the parser for the "write_data" command
    init_write_data_arg_parser(subparsers)

    return parser


def init_hello_arg_parser(subparsers):
    """
    Init hello command subparser
    """
    parser_hello = subparsers.add_parser(
        "hello",
        help="Scan multiple targets to detect OPC UA servers"
    )
    parser_hello.add_argument(
        "-i",
        "--ip_addresses",
        help="The target IP addresses (e.g. 127.0.0.1, 192.0.0.1-5)",
        required=True
    )
    parser_hello.add_argument(
        "-p",
        "--ports",
        help="The target ports (e.g. 4840, 80-85). The default port is 4840",
        default="4840"
    )
    parser_hello.add_argument(
        "-n",
        "--name",
        help=(
            "The name/path of the server (e.g opc:tcp://<IP>:<PORT>/<NAME>). "
            "Can be a string or a path to a file containing a list of names"
        ),
        default=""
    )
    parser_hello.add_argument(
        "-o",
        "--output",
        help=(
            "The path to a file where the server information will be written "
            "(JSON format)"
        )
    )
    parser_hello.add_argument(
        "-t",
        "--timeout",
        help=(
            "The timeout to consider a connection as failed in milliseconds "
            "(Default: 500)"
        ),
        default="500"
    )
    parser_hello.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display each tested connection"
    )
    parser_hello.add_argument(
        "-tfmt",
        "--table_format",
        choices=valid_table_formats,
        default="outline",
        metavar='FORMAT',
        help=(
            "The format of the summary table (see tabulate documentation "
            "for the list of accepted formats, e.g. outline, grid...)"
        )
    )


def init_server_config_arg_parser(subparsers):
    """
    Init server_config  command subparser
    """
    parser_server_config = subparsers.add_parser(
        "server_config",
        help=(
            "Retrieves information about the configuration of discovered OPC "
            "UA servers"
        )
    )
    parser_server_config.add_argument(
        "-t",
        "--targets",
        help=(
            "The target urls (e.g. opc.tcp://127.0.01:4840/ServerName, "
            "opc.tcp://127.0.01:4841/). It can be a path to the output file "
            "generated by the opcua_scan hello command. (e.g "
            "/path/to/hello_output.json)"
        ),
        required=True
    )
    parser_server_config.add_argument(
        "-a",
        "--authentication",
        help="The authentication method to be used (default: Anonymous)",
        choices=valid_auth_methods,
        default=valid_auth_methods[0]  # Anonymous
    )
    parser_server_config.add_argument(
        "-u",
        "--username",
        help="The username for the authentication",
        default=""
    )
    parser_server_config.add_argument(
        "-p",
        "--password",
        help="The password for the authentication",
        default=""
    )
    parser_server_config.add_argument(
        "-c",
        "--certificate",
        help="The certificate for the authentication and/or encryption",
        default=""
    )
    parser_server_config.add_argument(
        "-pk",
        "--private_key",
        help="The private key used for the authentication and/or encryption",
        default=""
    )
    parser_server_config.add_argument(
        "-m",
        "--mode",
        choices=list(valid_security_modes.keys()),
        default="None",
        help=(
            "The security mode of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_server_config.add_argument(
        "-po",
        "--policy",
        choices=list(valid_security_policies.keys()),
        default="None",
        help=(
            "The security policy of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_server_config.add_argument(
        "-nw",
        "--nodes_writable",
        action="store_true",
        help=(
            "Iterate all nodes from the chosen root and check for write "
            "permission"
        )
    )
    parser_server_config.add_argument(
        "-ne",
        "--nodes_executable",
        action="store_true",
        help=(
            "Iterate all nodes from the chosen root and look for executable "
            "methods"
        )
    )
    parser_server_config.add_argument(
        "-na",
        "--node_attributes",
        action='append',
        default=[],
        help=(
            "Specify an additional node attribute to retrieves in the file "
            "output. (Default attributes retrievied: NodeId, NodeClass, "
            "BrowseName, Value, UserRolePermissions, UserWriteMask, "
            "UserAccessLevel)"
        )
    )
    parser_server_config.add_argument(
        "-r",
        "--root_node",
        help=(
            "The ID of the node from which iterations will start "
            "(e.g. 2253, 'i=2253', 'ns=6;s=MyObjectsFolder')"
        )
    )
    parser_server_config.add_argument(
        "-o",
        "--output_verbose",
        help=(
            "The path to a file where more information about the server will "
            "be written (JSON format)"
        )
    )
    parser_server_config.add_argument(
        "-s",
        "--servers",
        action="store_true",
        help="Try to find other servers this server knows about"
    )
    parser_server_config.add_argument(
        "-xs",
        "--exclude-nodes",
        action="append",
        default=[],
        dest="exclude_nodes",
        metavar="NODE_ID",
        help=(
            "Skip this node and its entire subtree during iteration. "
            "Repeatable (e.g. -xs i=2253 -xs i=86). Accepts '2253', "
            "'i=2253' or 'ns=0;i=2253'"
        )
    )
    parser_server_config.add_argument(
        "-st",
        "--skip-standard",
        action="store_true",
        dest="skip_standard",
        help=(
            "Skip the standard OPC UA subtrees that are large and rarely "
            "relevant: Server (i=2253), Types (i=86), Views (i=87). "
            "Dramatically speeds up -nw / -ne on servers with a small "
            "application address space. "
            "Equivalent to: -xs i=2253 -xs i=86 -xs i=87"
        )
    )
    parser_server_config.add_argument(
        "-tfmt",
        "--table_format",
        choices=valid_table_formats,
        default="outline",
        metavar='FORMAT',
        help=(
            "The format of the summary table (see tabulate documentation "
            "for the list of accepted formats, e.g. outline, grid...)"
        )
    )

def init_read_data_arg_parser(subparsers):
    """
    Init read_data  command subparser
    """
    parser_read_data = subparsers.add_parser(
        "read_data",
        help=(
            "Retrieves information about the configuration of discovered OPC "
            "UA servers"
        )
    )
    parser_read_data.add_argument(
        "-t",
        "--targets",
        help=(
            "The target urls (e.g. opc.tcp://127.0.01:4840/ServerName, "
            "opc.tcp://127.0.01:4841/). It can be a path to the output file "
            "generated by the opcua_scan hello command. (e.g "
            "/path/to/hello_output.json)"
        ),
        required=True
    )
    parser_read_data.add_argument(
        "-a",
        "--authentication",
        help="The authentication method to be used (default: Anonymous)",
        choices=valid_auth_methods,
        default=valid_auth_methods[0]  # Anonymous
    )
    parser_read_data.add_argument(
        "-u",
        "--username",
        help="The username for the authentication",
        default=""
    )
    parser_read_data.add_argument(
        "-p",
        "--password",
        help="The password for the authentication",
        default=""
    )
    parser_read_data.add_argument(
        "-c",
        "--certificate",
        help="The certificate for the authentication and/or encryption",
        default=""
    )
    parser_read_data.add_argument(
        "-pk",
        "--private_key",
        help="The private key used for the authentication and/or encryption",
        default=""
    )
    parser_read_data.add_argument(
        "-m",
        "--mode",
        choices=list(valid_security_modes.keys()),
        default="None",
        help=(
            "The security mode of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_read_data.add_argument(
        "-po",
        "--policy",
        choices=list(valid_security_policies.keys()),
        default="None",
        help=(
            "The security policy of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_read_data.add_argument(
        "-r",
        "--root_node",
        help=(
            "The ID of the node from which iterations will start "
            "(e.g. 2253, 'i=2253', 'ns=6;s=MyObjectsFolder')"
        )
    )
    parser_read_data.add_argument(
        "-o",
        "--output_verbose",
        help=(
            "The path to a file where more information about the server will "
            "be written (JSON format)"
        )
    )
    parser_read_data.add_argument(
        "--single",
        action="store_true",
        help="Read a single address without browsing"
    )

def init_write_data_arg_parser(subparsers):
    """
    Init read_data  command subparser
    """
    parser_write_data = subparsers.add_parser(
        "write_data",
        help=(
            "Writes data to nodes"
        )
    )
    parser_write_data.add_argument(
        "-t",
        "--targets",
        help=(
            "The target urls (e.g. opc.tcp://127.0.01:4840/ServerName, "
            "opc.tcp://127.0.01:4841/). It can be a path to the output file "
            "generated by the opcua_scan hello command. (e.g "
            "/path/to/hello_output.json)"
        ),
        required=True
    )
    parser_write_data.add_argument(
        "-a",
        "--authentication",
        help="The authentication method to be used (default: Anonymous)",
        choices=valid_auth_methods,
        default=valid_auth_methods[0]  # Anonymous
    )
    parser_write_data.add_argument(
        "-u",
        "--username",
        help="The username for the authentication",
        default=""
    )
    parser_write_data.add_argument(
        "-p",
        "--password",
        help="The password for the authentication",
        default=""
    )
    parser_write_data.add_argument(
        "-c",
        "--certificate",
        help="The certificate for the authentication and/or encryption",
        default=""
    )
    parser_write_data.add_argument(
        "-pk",
        "--private_key",
        help="The private key used for the authentication and/or encryption",
        default=""
    )
    parser_write_data.add_argument(
        "-m",
        "--mode",
        choices=list(valid_security_modes.keys()),
        default="None",
        help=(
            "The security mode of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_write_data.add_argument(
        "-po",
        "--policy",
        choices=list(valid_security_policies.keys()),
        default="None",
        help=(
            "The security policy of the endpoint to which to connect "
            "(default: None)"
        )
    )
    parser_write_data.add_argument(
        "-r",
        "--root_node",
        required=True,
        help=(
            "The ID of the node to write to "
            "(e.g. 2253, 'i=2253', 'ns=2;i=2003', 'ns=6;s=MyVariable')"
        )
    )
    parser_write_data.add_argument(
        "-o",
        "--output_verbose",
        help=(
            "The path to a file where more information about the server will "
            "be written (JSON format)"
        )
    )
    parser_write_data.add_argument(
        "-d",
        "--data",
        help=(
            "Data to be written to the node"
        ),
        required=True
    )
    parser_write_data.add_argument(
        "-dt",
        "--dtype",
        help=(
            "Force the VariantType written to the node instead of auto-"
            "detecting it (e.g. Boolean, Int16, Int32, Int64, UInt16, UInt32, "
            "UInt64, Byte, SByte, Float, Double, String). When omitted, the "
            "type is read from the node itself."
        )
    )

##############################################################################
#                            Common utils section                            #
##############################################################################

def int_to_node_class(node_class):
    """
    Returns the security mode corresponding to the given string
    """
    return {
        1: ua.NodeClass.Object,
        2: ua.NodeClass.Variable,
        4: ua.NodeClass.Method,
        8: ua.NodeClass.ObjectType,
        16: ua.NodeClass.VariableType,
        32: ua.NodeClass.ReferenceType,
        64: ua.NodeClass.DataType,
        128: ua.NodeClass.View
    }.get(node_class) or ua.NodeClass.Unspecified


async def get_server_descriptions(client):
    """
    Retrieves the list of known servers by the server to which the client
    is connected
    """
    try:
        server_descriptions = await client.connect_and_find_servers()
        return server_descriptions
    except Exception:
        return []


def iterate_server_descriptions(server_descriptions):
    """
    Iterates all servers_descriptions and prints the relevant information
    """
    for server_description in server_descriptions:
        pretty_log("-" * 40)
        pretty_log(f"Server: {server_description.ApplicationName.Text}")
        pretty_log(f"Product URI: {server_description.ProductUri}")
        pretty_log(
            "Application Type: "
            f"{application_types[server_description.ApplicationType]}"
        )

        for url in server_description.DiscoveryUrls:
            pretty_log(f"Discovery url: {url}")
    if len(server_descriptions) > 0:
        pretty_log("-" * 40)


async def precheck_connection(client):
    """
    Sends an OPC UA Hello message to the server to which the client is
    connected.
    Returns True if the response is an OPCUA Acknowledge message, False
    otherwise.
    """
    try:
        await client.connect_socket()
        await client.send_hello()
        client.disconnect_socket()
    except Exception:
        try:
            client.disconnect_socket()
        except Exception:
            pass
        return False
    return True


async def get_endpoints(client):
    """
    Retrieves the endpoints of the server to which the client is connected
    """
    try:
        endpoints = await client.connect_and_get_server_endpoints()
        return endpoints
    except Exception:
        return []


def reset_msg_prefix():
    """
    Clear the per-target log prefix so run-level messages are not misattributed
    to the last scanned target.
    """
    global MSG_PREFIX
    MSG_PREFIX = ""


def pretty_log(message, lvl=""):
    """
    Prints the message and mimic metasploit output
    """
    if lvl == "error":
        full_message = "\033[91m\033[1m" + "[-] " + "\033[0m"
    elif lvl == "success":
        full_message = "\033[92m\033[1m" + "[+] " + "\033[0m"
    elif lvl == "critical":
        full_message = "\033[93m\033[1m" + "[!] " + "\033[0m"
    else:
        full_message = "\033[94m\033[1m" + "[*] " + "\033[0m"

    full_message += MSG_PREFIX + message
    print(full_message)


##############################################################################
#                                Run section                                 #
##############################################################################

if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
