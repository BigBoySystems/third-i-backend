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

CONFIG_PARSER = re.compile(r"^(\w+)=(.*)$", flags=re.MULTILINE)
ALLOWED_CONFIG_VALUE_CHARS = re.compile(r"^[a-zA-Z0-9:-]*$")
ALLOWED_CONFIG_KEYS = """
    photo_resolution
    video_width
    video_mode
    video_height
    video_fps
    video_bitrate
    video_profile
    rtmp_url
    rtmp_enabled
    mpegts_clients
    mpegts_enabled
    rtsp_enabled
    usb_enabled
    audio_enabled
    video_wb
    exposure
    contrast
    sharpness
    digitalgain
    wifi_iface
    wifi_ssid
    wifi_psk
    record_enabled
    record_time
    dec_enabled
    up_down
    swapcams
    udp_clients
    udp_enabled
    ws_enabled
""".split()


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
    }
    if password is not None:
        params["password"] = password
    async with captive_portal_get('http://localhost/connect', params=params) as resp:
        status = resp.status
    return status


async def is_portal():
    async with captive_portal_get('http://localhost/portal') as resp:
        return await resp.json()


async def start_ap():
    async with captive_portal_get('http://localhost/start-ap') as resp:
        status = resp.status
    return status


async def update_config(patch):
    config = await get_config()
    config.update(patch)
    content = "\n".join(["%s=%s" % (k, v) for (k, v) in config.items()])
    with open(app["config"], "wt") as fh:
        print(content, file=fh)
    return config


async def get_config():
    with open(app["config"], "rt") as fh:
        content = fh.read()
    config = OrderedDict([(x[0], x[1]) for x in CONFIG_PARSER.findall(content)])
    assert len(config) > 0, "configuration couldn't seem to be loaded"
    return config


###################################################################################################


async def route_list_networks(_request):
    json = await list_networks()
    return web.json_response(json)


async def route_connect(request):
    json = await request.json()
    try:
        res = await connect(json['essid'], json.get('password'))
    except KeyError:
        return web.json_response(
            {
            "success": False,
            "reason": "You must specify the `essid`.",
            }, status=400
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


async def route_portal(_request):
    res = await is_portal()
    return web.json_response({"portal": res})


async def route_start_ap(_request):
    res = await start_ap()
    if res < 400:
        return web.json_response({
            "success": True,
        })
    else:
        return web.json_response({
            "success": False,
        }, status=res)


async def route_config_update(request):
    json = await request.json()
    if not isinstance(json, dict):
        return web.json_response(
            {
            "success": False,
            "reason": "Only object accepted",
            }, status=400
        )
    for (k, v) in json.items():
        if k not in ALLOWED_CONFIG_KEYS:
            return web.json_response(
                {
                "success": False,
                "reason": "Key not allowed: %s" % k,
                }, status=403
            )
        if not ALLOWED_CONFIG_VALUE_CHARS.match(v):
            return web.json_response(
                {
                "success": False,
                "reason": "Invalid character in key's value: %s" % k,
                },
                status=403
            )
    await update_config(json)
    return web.json_response({
        "success": True,
    })


async def route_get_config(_request):
    json = await get_config()
    return web.json_response(json)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("third-i-backend")
app = web.Application()
app.add_routes(
    [
    web.get('/list-networks', route_list_networks),
    web.post('/connect', route_connect),
    web.get('/portal', route_portal),
    web.post('/start-ap', route_start_ap),
    web.patch('/config', route_config_update),
    web.get('/config', route_get_config),
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
    app["config"] = "/boot/stereopi.conf"

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
    app["config"] = os.environ["CONFIG"]
