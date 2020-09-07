#!/usr/bin/env python3

from aiohttp import web
from asyncio import sleep, subprocess, gather, Lock, shield
from collections import OrderedDict
import aiohttp
import argparse
import ast
import json
import logging
import mimetypes
import os
import re
import shutil
import sys
import urllib

if sys.version_info.major == 3 and sys.version_info.minor < 7:
    from asyncio import ensure_future as create_task
else:
    from asyncio import create_task

CONFIG_PARSER = re.compile(r"^(\w+)=(.*)$", flags=re.MULTILINE)
ALLOWED_CONFIG_VALUE_CHARS = re.compile(r"^[a-zA-Z0-9:. -]*$")
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


async def list_networks():
    logger.debug("Connecting to captive portal socket...")
    conn = aiohttp.UnixConnector(path=app["captive-portal"])
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get('http://localhost/list-networks') as resp:
            logger.debug("Received captive portal response: %s", resp.status)
            return await resp.json()


async def connect(essid, password):
    await sleep(1)
    params = {
        "essid": essid,
    }
    if password is not None:
        params["password"] = password
    logger.debug("Connecting to captive portal socket...")
    conn = aiohttp.UnixConnector(path=app["captive-portal"])
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get('http://localhost/connect', params=params) as resp:
            logger.debug("Received captive portal response: %s", resp.status)
            return resp.status


async def is_portal():
    logger.debug("Connecting to captive portal socket...")
    conn = aiohttp.UnixConnector(path=app["captive-portal"])
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get('http://localhost/portal') as resp:
            logger.debug("Received captive portal response: %s", resp.status)
            return await resp.json()


async def start_ap():
    await sleep(1)
    logger.debug("Connecting to captive portal socket...")
    conn = aiohttp.UnixConnector(path=app["captive-portal"])
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get('http://localhost/start-ap') as resp:
            logger.debug("Received captive portal response: %s", resp.status)
            return resp.status


def try_unescape(s):
    try:
        return ast.literal_eval(s)
    except Exception:
        return s


async def update_config(patch):
    async with app["lock"]:
        config = get_config()
        config.update(patch)
        query_string = urllib.parse.urlencode(config)
        await run_check("php", "/var/www/html/saveconfig.php", query_string)
        return config


def get_config():
    with open(app["config"], "rt") as fh:
        content = fh.read()
    config = OrderedDict([(x[0], str(try_unescape(x[1]))) for x in CONFIG_PARSER.findall(content)])
    assert len(config) > 0, "configuration couldn't seem to be loaded"
    return config


def generate_file_tree(path=None, trim=None):
    res = []
    if path is None:
        path = app["media"]
    if trim is None:
        trim = len(path) + 1
    for entry in os.scandir(path):
        if entry.is_symlink():
            continue
        p = os.path.join(path, entry.name)
        url = "/files/%s" % urllib.parse.quote(p[trim:])
        if entry.is_dir():
            res.append(
                {
                "directory": True,
                "name": entry.name,
                "path": path[trim:],
                "children": generate_file_tree(p, trim=trim),
                "url": url,
                }
            )
        if entry.is_file():
            res.append({
                "directory": False,
                "name": entry.name,
                "path": path[trim:],
                "url": url,
            })
    return res


class PathNotInMedia(Exception):
    pass


def check_path_in_media(path):
    canonical_path = os.path.realpath(path)
    if not canonical_path.startswith(app["media"]):
        raise PathNotInMedia()


# process management


async def run_proc(cmd, format_args, subprocess_args):
    format_args.update({
        "config": app["config"],
    })
    cmd = [x.format_map(format_args) for x in cmd]
    logger.debug("Running command: %s", cmd)
    return await subprocess.create_subprocess_exec(*cmd, **subprocess_args)


async def run_check(*cmd, **format_args):
    proc = await run_proc(cmd, format_args, {})
    rc = await proc.wait()
    if rc != 0:
        raise Exception("command execution failed (exit status != 0): %s" % (cmd, ))


async def run_capture_check(*cmd, **format_args):
    proc = await run_proc(cmd, format_args, {"stdout": subprocess.PIPE})
    rc = await proc.wait()
    if rc != 0:
        raise Exception("command execution failed (exit status != 0): %s" % (cmd, ))
    stdout = await proc.stdout.read()
    return stdout.decode("utf8")


###################################################################################################


async def route_list_networks(_request):
    json = await list_networks()
    return web.json_response(json)


async def route_connect(request):
    json = await request.json()
    try:
        create_task(connect(json['essid'], json.get('password')))
    except KeyError:
        return web.json_response(
            {
            "success": False,
            "reason": "You must specify the `essid`.",
            }, status=400
        )
    else:
        return web.json_response({
            "success": True,
        })


async def route_portal(_request):
    res = await is_portal()
    return web.json_response(res)


async def route_start_ap(_request):
    create_task(start_ap())
    return web.json_response({
        "success": True,
    })


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
    json = get_config()
    return web.json_response(json)


async def route_list_files(_request):
    json = {
        "name": "/",
        "path": "",
        "directory": True,
        "children": generate_file_tree(),
        "url": "/files",
    }
    return web.json_response(json)


async def route_get_file(request):
    try:
        path = os.path.join(app["media"], request.match_info['path'])
        check_path_in_media(path)
        (mime, _encoding) = mimetypes.guess_type(path)
    except PathNotInMedia:
        return web.Response(status=403)
    else:
        return web.Response(
            headers={
            "X-Accel-Redirect": path,
            "Content-Disposition": request.query.get("disposition", "inline"),
            "Content-Type": mime,
            }
        )


async def route_rename_file(request):
    try:
        filepath = os.path.join(app["media"], request.match_info['path'])
        check_path_in_media(filepath)
        json = await request.json()
        new_filepath = os.path.join(app["media"], json["dst"])
        check_path_in_media(new_filepath)
        os.rename(filepath, new_filepath)
    except PathNotInMedia:
        return web.json_response({
            "success": False,
            "reason": "invalid path",
        }, status=403)
    except KeyError:
        return web.json_response(
            {
            "success": False,
            "reason": "The key 'dst' is missing",
            }, status=400
        )
    except OSError as exc:
        return web.json_response({
            "success": False,
            "reason": str(exc),
        }, status=400)
    else:
        (path, name) = os.path.split(new_filepath)
        trim = len(app["media"]) + 1
        is_dir = os.path.isdir(new_filepath)
        file_entry = {
            "name": name,
            "path": path[trim:],
            "directory": is_dir,
            "url": "/files/%s" % urllib.parse.quote(new_filepath[trim:]),
        }
        if is_dir:
            file_entry["children"] = generate_file_tree(new_filepath, trim=trim)
        return web.json_response({
            "success": True,
            "file": file_entry,
        })


async def route_delete_file(request):
    try:
        filepath = os.path.join(app["media"], request.match_info['path'])
        check_path_in_media(filepath)
        try:
            os.remove(filepath)
        except IsADirectoryError:
            shutil.rmtree(filepath)
    except PathNotInMedia:
        return web.json_response({
            "success": False,
            "reason": "invalid path",
        }, status=403)
    except OSError as exc:
        return web.json_response({
            "success": False,
            "reason": str(exc),
        }, status=400)
    else:
        return web.json_response({
            "success": True,
        })


async def route_make_photo(_request):
    output = await run_capture_check("php", "/var/www/html/make_photo.php")
    res = json.loads(output)
    return web.json_response({
        "success": True,
        "filename": res["filename"],
    })


async def route_disk_usage(_request):
    (total, used, _free) = shutil.disk_usage(app["media"])
    return web.json_response({
        "used": used,
        "total": total,
    })


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("third-i-backend")
app = web.Application()
app["lock"] = Lock()
app.add_routes(
    [
    web.get('/list-networks', route_list_networks),
    web.post('/connect', route_connect),
    web.get('/portal', route_portal),
    web.post('/start-ap', route_start_ap),
    web.patch('/config', route_config_update),
    web.get('/config', route_get_config),
    web.get('/files', route_list_files),
    web.get('/files/{path:.+}', route_get_file),
    web.patch('/files/{path:.+}', route_rename_file),
    web.delete('/files/{path:.+}', route_delete_file),
    web.post('/make-photo', route_make_photo),
    web.get('/disk-usage', route_disk_usage),
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
    app["media"] = "/media"

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
    app["media"] = os.environ["MEDIA"]
