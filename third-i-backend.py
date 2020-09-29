#!/usr/bin/env python3

from aiohttp import web
from asyncio import sleep, subprocess, gather, Lock, shield
from collections import OrderedDict
from json import JSONDecodeError
import aiohttp
import argparse
import ast
import binascii
import json
import logging
import mimetypes
import os
import re
import serial_asyncio
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
RE_MESSAGE = re.compile(
    b"^(PARAM_ASK|PARAM_SET|REC_START|REC_STOP|WIFI_ON|WIFI_OFF)\|((?:([^:]+):)?(.*))\|0x([0-9a-fA-F]+)\]$"
)
LOG_LINES = 200
MAX_PRESETS = 10


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


async def start_wifi():
    logger.debug("Connecting to captive portal socket...")
    conn = aiohttp.UnixConnector(path=app["captive-portal"])
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get('http://localhost/wifi-on') as resp:
            logger.debug("Received captive portal response: %s", resp.status)
            return resp.status


async def stop_wifi():
    logger.debug("Connecting to captive portal socket...")
    conn = aiohttp.UnixConnector(path=app["captive-portal"])
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get('http://localhost/wifi-off') as resp:
            logger.debug("Received captive portal response: %s", resp.status)
            return resp.status


def try_unescape(s):
    try:
        return ast.literal_eval(s)
    except Exception:
        return s


class InvalidConfigPatch(Exception):
    pass


def verify_config(patch):
    for (k, v) in patch.items():
        if k not in ALLOWED_CONFIG_KEYS:
            raise InvalidConfigPatch("Key not allowed: %r" % k)
        if not isinstance(v, str):
            raise InvalidConfigPatch("Only string are allow in key's value")
        if not ALLOWED_CONFIG_VALUE_CHARS.match(v):
            raise InvalidConfigPatch("Invalid character in key's value: %s" % k)


async def update_config(patch):
    verify_config(patch)

    async with app["lock"]:
        logger.debug("Updatding configuration with: %r", patch)
        app["config"].update(patch)
        query_string = urllib.parse.urlencode(app["config"])
        await run_check("php", "/var/www/html/saveconfig.php", query_string)
        if "record_enabled" in patch:
            create_task(set_led(patch["record_enabled"] == "1"))
        return app["config"]


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


async def save_presets():
    if app["prod"]:
        await run_check("mount", "-o", "remount,rw", "/boot")
    with open(app["presets_json"], "wt") as fh:
        fh.write(json.dumps(app["presets"]))
    if app["prod"]:
        await run_check("mount", "-o", "remount,ro", "/boot")


# process management


async def run_proc(cmd, format_args, subprocess_args):
    format_args.update({
        "stereopi_conf": app["stereopi_conf"],
    })
    cmd = [str(x).format_map(format_args) for x in cmd]
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


async def process_messages(rx):
    while True:
        _ = await rx.readuntil(b"[")
        async with app["serial_lock"]:
            msg = await rx.readuntil(b"]")
            logger.debug("Serial message received: %r", msg)
            try:
                (data_type, key, value) = parse_message(msg)
            except Exception as exc:
                logger.error("Serial message could not be parsed: %s", exc)
            else:
                try:
                    logger.debug(
                        "Serial message parsed: data_type=%r, key=%r, value=%r", data_type, key,
                        value
                    )

                    if data_type == "PARAM_ASK":
                        send_message(
                            {
                            "type": "PARAM_GIVE",
                            "key": value,
                            "value": app["config"][value],
                            }
                        )
                    elif data_type == "PARAM_SET":
                        logger.info("Set parameter %s=%r", key, value)
                        await update_config({key: value})
                    elif data_type == "REC_START":
                        logger.info("Record started")
                        await update_config({
                            "record_enabled": "1",
                        })
                    elif data_type == "REC_STOP":
                        logger.info("Record stopped")
                        await update_config({
                            "record_enabled": "0",
                        })
                    elif data_type == "WIFI_ON":
                        logger.info("Activating WiFi...")
                        status = await start_wifi()
                        if status >= 400:
                            raise Exception("Could not start WiFi (HTTP status %s)" % status)
                        logger.info("WiFi activated")
                    elif data_type == "WIFI_OFF":
                        logger.info("Deactivating WiFi...")
                        status = await stop_wifi()
                        if status >= 400:
                            raise Exception("Could not stop WiFi (HTTP status %s)" % status)
                        logger.info("WiFi deactivated")
                except Exception as exc:
                    logger.exception("Could not answer to serial message: %s", exc)


def send_message(data):
    logger.debug("Sending serial message: %r", data)
    try:
        data_type = data["type"].encode().upper()
        key = data.get("key")
        value = data.get("value", "")
        if key is None:
            data_content = value.encode()
        else:
            data_content = ("%s:%s" % (key, value)).encode()
        checksum = binascii.crc32(data_type + b"|" + data_content)
        msg = b"[%s|%s|0x%x]" % (data_type, data_content, checksum)
    except Exception as exc:
        logger.exception("Message could not be sent")
    logger.debug("Sending serial message (raw): %r", msg)
    app["tx"].write(msg)


class InvalidMessage(Exception):
    def __str__(self):
        return "Invalid message"


class CorruptedMessage(Exception):
    def __init__(self, got, expected):
        self.got = got
        self.expected = expected

    def __str__(self):
        return "Corrupted message (got: %x, expected: %x)" % (self.got, self.expected)


def parse_message(msg):
    parsed = RE_MESSAGE.match(msg)
    if parsed is None:
        raise InvalidMessage()

    (data_type, data_content, key, value, checksum) = parsed.group(1, 2, 3, 4, 5)

    verify = binascii.crc32(data_type + b"|" + data_content)

    data_type = data_type.decode()
    if key is not None:
        key = key.decode()
    value = value.decode()
    checksum = int(checksum, 16)

    if checksum != verify:
        raise CorruptedMessage(checksum, verify)

    return (data_type, key, value)


async def set_led(state):
    if app["serial"] is None:
        return
    async with app["serial_lock"]:
        logger.info("Switching record led to: %r", bool(state))
        await sleep(1) # NOTE: leave some time to the ATmega328 to process the next message
        send_message({
            "type": ("LED_ON" if state else "LED_OFF"),
            "value": "-",
        })


###################################################################################################


async def route_list_networks(_request):
    json = await list_networks()
    return web.json_response(json)


async def route_connect(request):
    try:
        json = await request.json()
        create_task(connect(json['essid'], json.get('password')))
    except JSONDecodeError as exc:
        return web.json_response(
            {
            "success": False,
            "reason": "could not decode JSON: %s" % exc,
            }, status=400
        )
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
    try:
        json = await request.json()
    except JSONDecodeError as exc:
        return web.json_response(
            {
            "success": False,
            "reason": "could not decode JSON: %s" % exc,
            }, status=400
        )
    if not isinstance(json, dict):
        return web.json_response(
            {
            "success": False,
            "reason": "Only object accepted",
            }, status=400
        )
    if "preset" in json:
        name = json.pop("preset")
        try:
            new_config = dict(app["presets"][name])
            new_config.update(json)
            json = new_config
        except KeyError:
            return web.json_response(
                {
                "success": False,
                "reason": "preset %r does not exist" % name,
                }, status=404
            )
    try:
        config = await update_config(json)
    except InvalidConfigPatch as exc:
        return web.json_response({
            "success": False,
            "reason": str(exc),
        }, status=403)
    else:
        return web.json_response({
            "success": True,
            "config": config,
        })


async def route_get_config(_request):
    return web.json_response(app["config"])


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
    except JSONDecodeError as exc:
        return web.json_response(
            {
            "success": False,
            "reason": "could not decode JSON: %s" % exc,
            }, status=400
        )
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


async def route_captive_portal_logs(_request):
    output = await run_capture_check("journalctl", "-u", "captive-portal@*", "-n", LOG_LINES)
    return web.Response(text=output)


async def route_backend_logs(_request):
    output = await run_capture_check("journalctl", "-u", "third-i-backend@*", "-n", LOG_LINES)
    return web.Response(text=output)


async def route_list_preset(_request):
    return web.json_response({
        "success": True,
        "presets": list(app["presets"].keys()),
    })


async def route_get_preset(request):
    name = request.match_info["name"]
    try:
        config = app["presets"][name]
    except KeyError:
        return web.json_response(
            {
            "success": False,
            "reason": "preset %r does not exist" % name,
            }, status=404
        )
    else:
        return web.json_response({
            "success": True,
            "config": config,
        })


async def route_replace_preset(request):
    name = request.match_info["name"]
    if name not in app["presets"] and len(app["presets"]) >= MAX_PRESETS:
        return web.json_response(
            {
            "success": False,
            "reason": "maximum number of allowed presets reached",
            }, status=400
        )
    try:
        config = await request.json()
        verify_config(config)
        app["presets"][name] = config
        await save_presets()
    except KeyError:
        return web.json_response(
            {
            "success": False,
            "reason": "preset %r does not exist" % name,
            }, status=404
        )
    except JSONDecodeError as exc:
        return web.json_response(
            {
            "success": False,
            "reason": "could not decode JSON: %s" % exc,
            }, status=400
        )
    except InvalidConfigPatch as exc:
        return web.json_response(
            {
            "success": False,
            "reason": "invalid config: %s" % exc,
            }, status=400
        )
    else:
        return web.json_response({
            "success": True,
        })


async def route_delete_preset(request):
    name = request.match_info["name"]
    try:
        del app["presets"][name]
        await save_presets()
    except KeyError:
        return web.json_response(
            {
            "success": False,
            "reason": "preset %r does not exist" % name,
            }, status=404
        )
    else:
        return web.json_response({
            "success": True,
        })


async def get_config(app):
    with open(app["stereopi_conf"], "rt") as fh:
        content = fh.read()
    config = OrderedDict([(x[0], str(try_unescape(x[1]))) for x in CONFIG_PARSER.findall(content)])
    assert len(config) > 0, "configuration couldn't seem to be loaded"
    app["config"] = config


async def get_presets(app):
    try:
        with open(app["presets_json"], "rt") as fh:
            presets = json.loads(fh.read())
        assert isinstance(presets, dict), "'presets' is not an object"
        app["presets"] = presets
    except FileNotFoundError:
        app["presets"] = {}


async def serial_communication(app):
    if app["serial"] is None:
        logger.info("No serial interface selected")
        return
    rx, tx = await serial_asyncio.open_serial_connection(
        url=app["serial"], baudrate=app["serial_bauds"]
    )
    app["tx"] = tx
    app["process_messages"] = create_task(process_messages(rx))
    app["serial_lock"] = Lock()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("third-i-backend")
app = web.Application()
app["lock"] = Lock()
app.on_startup.append(get_config)
app.on_startup.append(get_presets)
app.on_startup.append(serial_communication)
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
    web.get('/logs/captive-portal', route_captive_portal_logs),
    web.get('/logs/backend', route_backend_logs),
    web.get('/list-presets', route_list_preset),
    web.get('/preset/{name}', route_get_preset),
    web.post('/preset/{name}', route_replace_preset),
    web.delete('/preset/{name}', route_delete_preset),
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
    "--serial",
    type=str,
    help="use serial interface",
)
parser.add_argument(
    "--bauds",
    type=int,
    default=115200,
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

    app["prod"] = True
    app["captive-portal"] = args.captive_portal
    app["stereopi_conf"] = "/boot/stereopi.conf"
    app["presets_json"] = "/boot/presets.json"
    app["media"] = "/media"
    app["serial"] = args.serial
    app["serial_bauds"] = args.bauds

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
    app["prod"] = False
    app["captive-portal"] = os.environ["CAPTIVE_PORTAL"]
    app["stereopi_conf"] = os.environ["STEREOPI_CONF"]
    app["presets_json"] = os.environ["PRESETS_JSON"]
    app["media"] = os.environ["MEDIA"]
    app["serial"] = os.environ.get("SERIAL")
    app["serial_bauds"] = int(os.environ.get("SERIAL_BAUDS", "115200"))
