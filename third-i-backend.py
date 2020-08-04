#!/usr/bin/env python3

from aiohttp import web
from asyncio import sleep, subprocess, gather, Lock, shield
from collections import OrderedDict
import argparse
import ast
import logging
import os
import re
import sys

if sys.version_info.major == 3 and sys.version_info.minor < 7:
    from asyncio import ensure_future as create_task
else:
    from asyncio import create_task



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("third-i-backend")
app = web.Application()
#app.on_startup.append(start_ap_on_startup)
#app.on_cleanup.append(kill_daemons_on_cleanup)
#app.on_cleanup.append(shutdown_interface)
#app.add_routes([web.get("/start-ap", route_start_ap)])
#app.add_routes([web.get("/list-networks", route_list_networks)])
#app.add_routes([web.get("/connect", route_connect)])
#app.add_routes([web.get("/portal", route_ap)])

parser = argparse.ArgumentParser(description="Backend for the thingy")
parser.add_argument(
    "--host",
    type=str,
    required=True,
    help="open the server on a TCP/IP host",
)
parser.add_argument(
    "--port",
    type=int,
    required=True,
    help="open the server on a TCP/IP port",
)
parser.add_argument(
    "--debug",
    action="store_true",
    help="show debug logs",
)
parser.add_argument(
    "captive_portal",
    type=str,
    help="captive portal socket",
)

if __name__ == "__main__":
    # production mode
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    app["captive-portal"] = args.captive_portal

    web.run_app(
        app,
        host=args.host,
        port=args.port,
    )
else:
    if "CAPTIVE_PORTAL" not in os.environ:
        print("Missing `CAPTIVE_PORTAL` in environment variables.", file=sys.stderr)
        print("Example: CAPTIVE_PORTAL=/run/captive-portal.sock pipenv run dev", file=sys.stderr)
        sys.exit(1)

    logger.setLevel(logging.DEBUG)

    # development mode
    app["captive-portal"] = os.environ["CAPTIVE_PORTAL"]
