#!/usr/bin/env python3

from aiohttp import web
from asyncio import sleep, subprocess, gather, Lock, shield
from collections import OrderedDict
from contextlib import asynccontextmanager
import aiohttp
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


@asynccontextmanager
async def captive_portal_get(*args, **kwargs):
    logger.debug("Connecting to captive portal socket...")
    conn = aiohttp.UnixConnector(path=app["captive-portal"])
    async with aiohttp.ClientSession(connector=conn) as session:
        logger.debug("Query captive portal: args=%r kwargs=%r", args, kwargs)
        async with session.get(*args, **kwargs) as resp:
            logger.debug("Received captive portal response: %s", resp.status)
            yield resp


async def list_networks():
    async with captive_portal_get('http://localhost/list-networks') as resp:
        return await resp.json()


async def connect(essid, password):
    params = {
        "essid": essid,
        "password": password,
    }
    async with captive_portal_get('http://localhost/connect', params=params) as resp:
        status = resp.status
    return status


async def is_portal():
    async with captive_portal_get('http://localhost/portal') as resp:
        return await resp.json()


###################################################################################################


async def route_list_networks(request):
    json = await list_networks()
    return web.json_response(json)


async def route_connect(request):
    json = await request.json()
    try:
        res = await connect(json['essid'], json['password'])
    except KeyError:
        return web.json_response(
            {
            "success": False,
            "reason": "You must specify the `essid` and the `password`.",
            },
            status=400
        )
    else:
        if res < 400:
            return web.json_response({
                "success": True,
            })
        else:
            return web.json_response({
                "success": False,
            }, status=res)


async def route_portal(request):
    res = await is_portal()
    return web.json_response({"portal": res})


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("third-i-backend")
app = web.Application()
app.add_routes(
    [
    web.get('/list-networks', route_list_networks),
    web.post('/connect', route_connect),
    web.get('/portal', route_portal),
    ]
)

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
