#!/usr/bin/env python3
"""sing-quota：Linux 终端配置生成器。"""

import argparse
import base64
import configparser
import copy
import curses
import json
import math
from ipaddress import ip_address
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
SLICES = ROOT / "slices"
WGCF = ROOT / "wgcf"
CONF_DIR = ROOT / "sing-conf"
DATA_DIR = ROOT / "data"
CONFIG = CONF_DIR / "config.json"
BACKUP = CONF_DIR / "config.json.bak"
QUOTAS = CONF_DIR / "quotas.json"
QUOTAS_BACKUP = CONF_DIR / "quotas.json.bak"
COMPOSE = ROOT / "compose.yml"
COMPOSE_BACKUP = ROOT / "compose.yml.bak"
REPOSITORY = "SagerNet/sing-box"
RELEASES_URL = f"https://api.github.com/repos/{REPOSITORY}/releases"
WGCF_IMAGE = "virb3/wgcf:latest"
DEFAULT_REALITY_SERVER = "developer.download.nvidia.com"
LEGACY_DEFAULT_REALITY_SERVER = "cdn-dynmedia-1.microsoft.com"
IMAGE_NAMES = {
    "sing-box": "sing-quota-sing-box",
    "manager": "sing-quota-manager",
}
VERSION_PATTERN = re.compile(r"^v?\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.-]+)?$")
SECRET_KEYS = {
    "access_token",
    "device_id",
    "license_key",
    "password",
    "private_key",
    "uuid",
}

DEFAULT_SLICES = {
    "log": {"level": "info", "timestamp": True},
    "wireguard": {
        "enabled": False,
        "tag": "wg-out",
        "system": False,
        "profile": "wgcf/wgcf-profile.conf",
    },
    "runtime": {"sing_box_image": "", "public_ipv4": "", "public_ipv6": ""},
    "users": [],
    "vless-reality": {
        "enabled": True,
        "tag": "vless-reality-in",
        "listen": "::",
        "listen_port": 8443,
        "flow": "xtls-rprx-vision",
        "tls": {
            "enabled": True,
            "server_name": DEFAULT_REALITY_SERVER,
            "reality": {
                "enabled": True,
                "handshake": {
                    "server": DEFAULT_REALITY_SERVER,
                    "server_port": 443,
                },
                "private_key": "",
                "public_key": "",
                "short_id": [],
                "max_time_difference": "1m",
            },
        },
    },
    "shadowsocks": {
        "enabled": True,
        "tag": "ss-in",
        "listen": "::",
        "listen_port": 8388,
        "method": "2022-blake3-aes-128-gcm",
        "password": "",
    },
    "route": {"final": "direct", "basic_rules": []},
}


def slice_path(name):
    return SLICES / f"{name}.json"


def save_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(value, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError(f"缺少文件：{path}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"JSON 格式错误：{path} 第 {error.lineno} 行") from error


def initialize_slices():
    SLICES.mkdir(mode=0o700, parents=True, exist_ok=True)
    created = []
    for name, default in DEFAULT_SLICES.items():
        path = slice_path(name)
        if not path.exists():
            value = legacy_users() if name == "users" else copy.deepcopy(default)
            save_json(path, value or copy.deepcopy(default))
            created.append(path.name)
    migrate_default_nodes()
    return created


def legacy_users():
    users = {}
    for name, credential in (
        ("vless-reality", "uuid"),
        ("shadowsocks", "shadowsocks_password"),
    ):
        path = slice_path(name)
        if not path.exists():
            continue
        value = load_json(path)
        for user in value.get("users", []) if isinstance(value, dict) else []:
            if not isinstance(user, dict) or not isinstance(user.get("name"), str):
                continue
            entry = users.setdefault(user["name"], {"name": user["name"]})
            if credential == "uuid":
                entry[credential] = user.get("uuid", "")
            else:
                entry[credential] = user.get("password", "")
    return list(users.values())


def migrate_default_nodes():
    vless_path = slice_path("vless-reality")
    vless = load_json(vless_path)
    tls = vless.get("tls", {}) if isinstance(vless, dict) else {}
    reality = tls.get("reality", {}) if isinstance(tls, dict) else {}
    if (
        vless.get("enabled") is False
        and tls.get("server_name") in (None, "")
        and reality.get("handshake", {}).get("server") in (None, "")
        and not reality.get("private_key")
        and not reality.get("short_id")
    ):
        vless["enabled"] = True
        tls["server_name"] = DEFAULT_REALITY_SERVER
        reality.setdefault("handshake", {})["server"] = DEFAULT_REALITY_SERVER
        reality["handshake"].setdefault("server_port", 443)
        tls["reality"] = reality
        vless["tls"] = tls
        save_slice("vless-reality", vless)

    if tls.get("server_name") == LEGACY_DEFAULT_REALITY_SERVER:
        tls["server_name"] = DEFAULT_REALITY_SERVER
        save_slice("vless-reality", vless)
    handshake = reality.get("handshake", {})
    if handshake.get("server") == LEGACY_DEFAULT_REALITY_SERVER:
        handshake["server"] = DEFAULT_REALITY_SERVER
        reality["handshake"] = handshake
        tls["reality"] = reality
        vless["tls"] = tls
        save_slice("vless-reality", vless)

    shadowsocks_path = slice_path("shadowsocks")
    shadowsocks = load_json(shadowsocks_path)
    if (
        shadowsocks.get("enabled") is False
        and not shadowsocks.get("password")
        and shadowsocks.get("tag") == "ss-in"
        and shadowsocks.get("listen") == "::"
        and shadowsocks.get("listen_port") == 8388
    ):
        shadowsocks["enabled"] = True
        save_slice("shadowsocks", shadowsocks)


def load_slices():
    initialize_slices()
    values = {}
    for name, default in DEFAULT_SLICES.items():
        value = load_json(slice_path(name))
        if not isinstance(value, type(default)):
            raise RuntimeError(f"切片类型错误：{slice_path(name)}")
        values[name] = value
    return values


def save_slice(name, value):
    save_json(slice_path(name), value)


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{label}不能为空")
    return value.strip()


def boolean(value, label):
    if not isinstance(value, bool):
        raise RuntimeError(f"{label}必须是布尔值")
    return value


def port(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise RuntimeError(f"{label}必须在 1 到 65535 之间")
    return value


def quota_limit(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError("流量额度必须是数字")
    value = float(value)
    if not math.isfinite(value) or value < 0:
        raise RuntimeError("流量额度必须是大于等于 0 的有限数字")
    return value


def reset_day(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 31:
        raise RuntimeError("重置日期必须在 0 到 31 之间")
    return value


def fetch_public_address(url, version):
    try:
        request = Request(url, headers={"User-Agent": "sing-quota"})
        with urlopen(request, timeout=10) as response:
            address = ip_address(response.read(128).decode("ascii").strip())
    except (OSError, UnicodeDecodeError, ValueError, HTTPError, URLError) as error:
        raise RuntimeError(str(error)) from error
    if address.version != version:
        raise RuntimeError(f"查询服务返回的不是 IPv{version} 地址：{address}")
    return str(address)


def refresh_public_addresses():
    runtime = load_slices()["runtime"]
    results = []
    failures = []
    for version, url, key in (
        (4, "https://api.ipify.org", "public_ipv4"),
        (6, "https://api6.ipify.org", "public_ipv6"),
    ):
        try:
            address = fetch_public_address(url, version)
        except RuntimeError as error:
            failures.append(f"IPv{version} 未获取：{error}")
        else:
            runtime[key] = address
            results.append(f"IPv{version}：{address}")
    if results:
        save_slice("runtime", runtime)
    if not results:
        raise RuntimeError("无法获取公网地址：\n" + "\n".join(failures))
    return "\n".join(results + failures)


def resolve_profile(value):
    path = Path(text(value, "WireGuard profile 路径"))
    return path if path.is_absolute() else ROOT / path


def split_values(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_endpoint(value):
    value = text(value, "Peer Endpoint")
    if value.startswith("["):
        host, separator, port_text = value[1:].partition("]:")
        if not separator:
            raise RuntimeError("Peer Endpoint 的 IPv6 格式无效")
    else:
        host, separator, port_text = value.rpartition(":")
        if not separator:
            raise RuntimeError("Peer Endpoint 必须包含端口")
    try:
        peer_port = port(int(port_text), "Peer 端口")
    except ValueError as error:
        raise RuntimeError("Peer 端口必须是整数") from error
    return text(host, "Peer 地址"), peer_port


def parse_profile(path):
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    try:
        with path.open(encoding="utf-8") as file:
            parser.read_file(file)
        interface = parser["Interface"]
        peer = parser["Peer"]
    except (OSError, KeyError, configparser.Error) as error:
        raise RuntimeError(f"无法解析 wgcf profile：{path}") from error

    addresses = split_values(text(interface.get("Address", ""), "Interface.Address"))
    if not addresses:
        raise RuntimeError("Interface.Address不能为空")
    host, peer_port = parse_endpoint(peer.get("Endpoint", ""))
    try:
        mtu = port(int(interface.get("MTU", "0")), "Interface.MTU")
    except ValueError as error:
        raise RuntimeError("Interface.MTU 必须是整数") from error
    result = {
        "private_key": text(interface.get("PrivateKey", ""), "Interface.PrivateKey"),
        "address": addresses,
        "mtu": mtu,
        "peer": {
            "public_key": text(peer.get("PublicKey", ""), "Peer.PublicKey"),
            "address": host,
            "port": peer_port,
            "allowed_ips": split_values(
                text(peer.get("AllowedIPs", ""), "Peer.AllowedIPs")
            ),
        },
    }
    reserved = peer.get("Reserved", "")
    if reserved:
        values = split_values(reserved)
        try:
            values = [int(item) for item in values]
        except ValueError as error:
            raise RuntimeError("Peer.Reserved 必须是整数列表") from error
        if len(values) != 3 or any(not 0 <= item <= 255 for item in values):
            raise RuntimeError("Peer.Reserved 必须是三个 0 到 255 的整数")
        result["peer"]["reserved"] = values
    return result


def unique_tags(*groups):
    tags = set()
    for tag in groups:
        tag = text(tag, "tag")
        if tag in tags:
            raise RuntimeError(f"tag 重复：{tag}")
        tags.add(tag)
    return tags


def validate_global_users(users, need_vless, need_shadowsocks):
    if not isinstance(users, list) or not users:
        raise RuntimeError("至少需要一个全局用户")
    names = set()
    normalized = []
    for index, user in enumerate(users, start=1):
        if not isinstance(user, dict):
            raise RuntimeError(f"第 {index} 个用户格式错误")
        name = text(user.get("name", ""), f"第 {index} 个用户名")
        if name in names:
            raise RuntimeError(f"用户名重复：{name}")
        names.add(name)
        normalized.append(
            {
                "name": name,
                "uuid": text(user.get("uuid", ""), f"{name} 的 VLESS UUID")
                if need_vless
                else user.get("uuid", ""),
                "shadowsocks_password": text(
                    user.get("shadowsocks_password", ""),
                    f"{name} 的 Shadowsocks 密码",
                )
                if need_shadowsocks
                else user.get("shadowsocks_password", ""),
                "limit_gb": quota_limit(user.get("limit_gb", 0)),
                "reset_day": reset_day(user.get("reset_day", 0)),
            }
        )
    return normalized


def build_wireguard(settings):
    profile = parse_profile(resolve_profile(settings.get("profile", "")))
    peer = profile["peer"]
    if not peer["allowed_ips"]:
        raise RuntimeError("Peer.AllowedIPs不能为空")
    endpoint = {
        "type": "wireguard",
        "tag": text(settings.get("tag", ""), "WireGuard tag"),
        "system": boolean(settings.get("system"), "WireGuard system"),
        "mtu": profile["mtu"],
        "address": profile["address"],
        "private_key": profile["private_key"],
        "peers": [peer],
    }
    return endpoint


def build_vless(settings, global_users):
    flow = text(settings.get("flow", ""), "VLESS flow")
    users = [
        {"name": user["name"], "uuid": user["uuid"], "flow": flow}
        for user in global_users
    ]

    tls = settings.get("tls")
    if not isinstance(tls, dict) or not boolean(
        tls.get("enabled"), "VLESS TLS enabled"
    ):
        raise RuntimeError("VLESS Reality 必须启用 TLS")
    reality = tls.get("reality")
    if not isinstance(reality, dict) or not boolean(
        reality.get("enabled"), "VLESS Reality enabled"
    ):
        raise RuntimeError("VLESS Reality必须启用")
    handshake = reality.get("handshake")
    if not isinstance(handshake, dict):
        raise RuntimeError("VLESS Reality handshake 格式错误")
    short_id = reality.get("short_id")
    if not isinstance(short_id, list) or not short_id:
        raise RuntimeError("VLESS Reality short_id 至少需要一个值")
    short_id = [text(item, "VLESS Reality short_id") for item in short_id]

    return {
        "type": "vless",
        "tag": text(settings.get("tag", ""), "VLESS tag"),
        "listen": text(settings.get("listen", ""), "VLESS 监听地址"),
        "listen_port": port(settings.get("listen_port"), "VLESS 监听端口"),
        "users": users,
        "tls": {
            "enabled": True,
            "server_name": text(tls.get("server_name", ""), "VLESS server_name"),
            "reality": {
                "enabled": True,
                "handshake": {
                    "server": text(
                        handshake.get("server", ""), "VLESS handshake server"
                    ),
                    "server_port": port(
                        handshake.get("server_port"), "VLESS handshake 端口"
                    ),
                },
                "private_key": text(
                    reality.get("private_key", ""), "VLESS Reality private_key"
                ),
                "short_id": short_id,
                "max_time_difference": text(
                    reality.get("max_time_difference", ""),
                    "VLESS max_time_difference",
                ),
            },
        },
    }


def build_shadowsocks(settings, global_users):
    users = [
        {"name": user["name"], "password": user["shadowsocks_password"]}
        for user in global_users
    ]
    return {
        "type": "shadowsocks",
        "tag": text(settings.get("tag", ""), "Shadowsocks tag"),
        "listen": text(settings.get("listen", ""), "Shadowsocks 监听地址"),
        "listen_port": port(settings.get("listen_port"), "Shadowsocks 监听端口"),
        "method": text(settings.get("method", ""), "Shadowsocks method"),
        "password": text(settings.get("password", ""), "Shadowsocks 服务端密码"),
        "users": users,
    }


def build_config(values):
    log = values["log"]
    if not isinstance(log, dict):
        raise RuntimeError("日志切片格式错误")
    config = {
        "log": {
            "level": text(log.get("level", ""), "日志等级"),
            "timestamp": boolean(log.get("timestamp"), "日志时间戳"),
        },
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }
    wireguard = values["wireguard"]
    vless = values["vless-reality"]
    shadowsocks = values["shadowsocks"]
    vless_enabled = boolean(vless.get("enabled"), "VLESS enabled")
    shadowsocks_enabled = boolean(shadowsocks.get("enabled"), "Shadowsocks enabled")
    global_users = validate_global_users(
        values["users"], vless_enabled, shadowsocks_enabled
    )
    tags = {"direct"}
    inputs = set()
    targets = {"direct"}

    if boolean(wireguard.get("enabled"), "WireGuard enabled"):
        endpoint = build_wireguard(wireguard)
        tags = unique_tags(*tags, endpoint["tag"])
        targets.add(endpoint["tag"])
        config["endpoints"] = [endpoint]

    inbounds = []
    if vless_enabled:
        inbound = build_vless(vless, global_users)
        tags = unique_tags(*tags, inbound["tag"])
        inputs.add(inbound["tag"])
        inbounds.append(inbound)

    if shadowsocks_enabled:
        inbound = build_shadowsocks(shadowsocks, global_users)
        tags = unique_tags(*tags, inbound["tag"])
        inputs.add(inbound["tag"])
        inbounds.append(inbound)

    if not inbounds:
        raise RuntimeError("至少启用一个入站协议")
    config["inbounds"] = inbounds

    route_settings = values["route"]
    if not isinstance(route_settings, dict):
        raise RuntimeError("路由切片格式错误")
    final = text(route_settings.get("final", ""), "路由最终出口")
    if final not in targets:
        raise RuntimeError(f"路由最终出口不存在：{final}")
    basic_rules = route_settings.get("basic_rules")
    if not isinstance(basic_rules, list):
        raise RuntimeError("基础路由规则必须是列表")

    rules = []
    routed_inputs = set()
    for index, rule in enumerate(basic_rules, start=1):
        if not isinstance(rule, dict):
            raise RuntimeError(f"第 {index} 条基础路由格式错误")
        inbound = text(rule.get("inbound", ""), f"第 {index} 条路由入站")
        outbound = text(rule.get("outbound", ""), f"第 {index} 条路由出口")
        if inbound not in inputs:
            raise RuntimeError(f"路由引用了未启用的入站：{inbound}")
        if outbound not in targets:
            raise RuntimeError(f"路由引用了不存在的出口：{outbound}")
        if inbound in routed_inputs:
            raise RuntimeError(f"同一入站只能有一条基础路由：{inbound}")
        routed_inputs.add(inbound)
        rules.append({"inbound": inbound, "action": "route", "outbound": outbound})

    config["route"] = {"rules": rules, "final": final}
    config["experimental"] = {
        "v2ray_api": {
            "listen": "0.0.0.0:10085",
            "stats": {
                "enabled": True,
                "users": [user["name"] for user in global_users],
            },
        }
    }
    return config


def build_quotas(users):
    return {
        user["name"]: {
            "limit_gb": user["limit_gb"],
            "reset_day": user["reset_day"],
        }
        for user in users
    }


def public_hosts(values):
    runtime = values["runtime"]
    hosts = []
    for version, key in ((4, "public_ipv4"), (6, "public_ipv6")):
        value = runtime.get(key, "")
        if not value:
            continue
        try:
            address = ip_address(value)
        except ValueError as error:
            raise RuntimeError(f"保存的公网 IPv{version} 地址无效：{value}") from error
        if address.version != version:
            raise RuntimeError(f"保存的公网地址版本不符：{value}")
        hosts.append(f"[{address}]" if version == 6 else str(address))
    return hosts


def vless_link(user, values, host):
    vless = values["vless-reality"]
    if not boolean(vless.get("enabled"), "VLESS enabled"):
        raise RuntimeError("VLESS Reality 未启用")
    tls = vless.get("tls", {})
    reality = tls.get("reality", {}) if isinstance(tls, dict) else {}
    short_ids = reality.get("short_id")
    if not isinstance(short_ids, list) or not short_ids:
        raise RuntimeError("Reality Short ID 未生成，请先生成配置")
    parameters = urlencode(
        {
            "encryption": "none",
            "flow": text(vless.get("flow", ""), "VLESS flow"),
            "security": "reality",
            "sni": text(tls.get("server_name", ""), "Reality Server name"),
            "fp": "random",
            "pbk": text(reality.get("public_key", ""), "Reality 公钥"),
            "sid": text(short_ids[0], "Reality Short ID"),
            "type": "tcp",
            "headerType": "none",
        }
    )
    uuid = text(user.get("uuid", ""), "用户 UUID")
    name = quote(f"{text(user.get('name', ''), '用户名')}-VLESS", safe="")
    listen_port = port(vless.get("listen_port"), "VLESS 监听端口")
    return f"vless://{uuid}@{host}:{listen_port}?{parameters}#{name}"


def shadowsocks_link(user, values, host):
    settings = values["shadowsocks"]
    if not boolean(settings.get("enabled"), "Shadowsocks enabled"):
        raise RuntimeError("Shadowsocks 未启用")
    credential = ":".join(
        (
            text(settings.get("method", ""), "Shadowsocks method"),
            text(settings.get("password", ""), "Shadowsocks 服务端密码"),
            text(user.get("shadowsocks_password", ""), "用户 Shadowsocks 密码"),
        )
    )
    encoded = base64.urlsafe_b64encode(credential.encode()).decode().rstrip("=")
    name = quote(f"{text(user.get('name', ''), '用户名')}-SS", safe="")
    return f"ss://{encoded}@{host}:{port(settings.get('listen_port'), 'Shadowsocks 监听端口')}#{name}"


def node_links(user):
    refresh_error = None
    try:
        refresh_public_addresses()
    except RuntimeError as error:
        refresh_error = error
    values = load_slices()
    hosts = public_hosts(values)
    if not hosts:
        raise refresh_error or RuntimeError("未获取到公网地址")
    links = []
    for host in hosts:
        links.append(vless_link(user, values, host))
        links.append(shadowsocks_link(user, values, host))
    return "\n\n".join(links)


def manager_image(singbox_image):
    prefix = f"{IMAGE_NAMES['sing-box']}:"
    if not singbox_image.startswith(prefix):
        raise RuntimeError(f"当前 sing-box 镜像名称无效：{singbox_image}")
    return f"{IMAGE_NAMES['manager']}:{singbox_image[len(prefix):]}"


def compose_ports(values):
    ports = []
    used = set()

    def add(value, protocol):
        value = port(value, f"{protocol.upper()} 端口")
        key = (value, protocol)
        if key in used:
            raise RuntimeError(f"端口冲突：{value}/{protocol}")
        used.add(key)
        ports.append(f"{value}:{value}/{protocol}")

    vless = values["vless-reality"]
    if boolean(vless.get("enabled"), "VLESS enabled"):
        add(vless.get("listen_port"), "tcp")
    shadowsocks = values["shadowsocks"]
    if boolean(shadowsocks.get("enabled"), "Shadowsocks enabled"):
        add(shadowsocks.get("listen_port"), "tcp")
        add(shadowsocks.get("listen_port"), "udp")
    return ports


def build_compose(values, singbox_image, quota_image):
    lines = [
        "services:",
        "  sing-box:",
        f"    image: {json.dumps(singbox_image)}",
        "    restart: unless-stopped",
        "    logging:",
        "      driver: local",
        "      options:",
        '        max-size: "10m"',
        '        max-file: "3"',
        "    volumes:",
        '      - "./sing-conf:/etc/sing-box:ro"',
        "    ports:",
    ]
    lines.extend(f"      - {json.dumps(value)}" for value in compose_ports(values))
    lines.extend(
        [
            "",
            "  quota-manager:",
            f"    image: {json.dumps(quota_image)}",
            "    restart: unless-stopped",
            "    logging:",
            "      driver: local",
            "      options:",
            '        max-size: "10m"',
            '        max-file: "3"',
            "    depends_on:",
            "      - sing-box",
            '    pid: "service:sing-box"',
            "    volumes:",
            '      - "./sing-conf:/etc/sing-box"',
            '      - "./data:/var/lib/sing-quota"',
            "",
        ]
    )
    return "\n".join(lines)


def save_text(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def backup(path, destination):
    if path.exists():
        shutil.copy2(path, destination)
        os.chmod(destination, 0o600)


def check_config(config, image):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "config.json"
        save_json(path, config)
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{Path(directory).resolve()}:/etc/sing-box:ro",
                image,
                "check",
                "-c",
                "/etc/sing-box/config.json",
            ],
            capture_output=True,
            text=True,
        )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip() or "未知错误"
        raise RuntimeError(f"sing-box 配置校验失败：{detail}")


def materialize_generated_defaults(values):
    vless = values["vless-reality"]
    if boolean(vless.get("enabled"), "VLESS enabled"):
        tls = vless.setdefault(
            "tls", copy.deepcopy(DEFAULT_SLICES["vless-reality"]["tls"])
        )
        tls.setdefault("enabled", True)
        if not tls.get("server_name"):
            tls["server_name"] = DEFAULT_REALITY_SERVER
        reality = tls.setdefault(
            "reality", copy.deepcopy(DEFAULT_SLICES["vless-reality"]["tls"]["reality"])
        )
        reality.setdefault("enabled", True)
        handshake = reality.setdefault("handshake", {})
        if not handshake.get("server"):
            handshake["server"] = DEFAULT_REALITY_SERVER
        handshake.setdefault("server_port", 443)
        if not reality.get("private_key"):
            private_key, public_key = generate_reality_keypair()
            reality["private_key"] = private_key
            reality["public_key"] = public_key
        if not reality.get("short_id"):
            reality["short_id"] = [generated_value("rand", "--hex", "8")]
        save_slice("vless-reality", vless)

    shadowsocks = values["shadowsocks"]
    if boolean(shadowsocks.get("enabled"), "Shadowsocks enabled"):
        if not shadowsocks.get("password"):
            shadowsocks["password"] = generate_shadowsocks_password(
                text(shadowsocks.get("method", ""), "Shadowsocks method")
            )
        save_slice("shadowsocks", shadowsocks)


def write_generated():
    values = load_slices()
    singbox_image = active_singbox_image()
    quota_image = manager_image(singbox_image)
    if not image_exists(quota_image):
        raise RuntimeError(f"当前配套 quota-manager 镜像不存在：{quota_image}")
    users = validate_global_users(
        values["users"],
        boolean(values["vless-reality"].get("enabled"), "VLESS enabled"),
        boolean(values["shadowsocks"].get("enabled"), "Shadowsocks enabled"),
    )
    materialize_generated_defaults(values)
    config = build_config(values)
    check_config(config, singbox_image)
    compose = build_compose(values, singbox_image, quota_image)
    CONF_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup(CONFIG, BACKUP)
    backup(QUOTAS, QUOTAS_BACKUP)
    backup(COMPOSE, COMPOSE_BACKUP)
    save_json(CONFIG, config)
    save_json(QUOTAS, build_quotas(users))
    save_text(COMPOSE, compose)
    return config


def redacted(value):
    if isinstance(value, list):
        return [redacted(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "***" if key.lower() in SECRET_KEYS else redacted(item)
            for key, item in value.items()
        }
    return value


def ensure_docker():
    if shutil.which("docker") is None:
        raise RuntimeError("未找到 docker 命令，请先安装 Docker")
    result = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip() or "未知错误"
        raise RuntimeError(f"Docker daemon 不可用：{detail}")


def wgcf_command(action, interactive=False):
    WGCF.mkdir(mode=0o700, parents=True, exist_ok=True)
    command = ["docker", "run", "--rm"]
    if interactive:
        command.append("-it")
    command.extend(
        [
            "-v",
            f"{WGCF.resolve()}:/data",
            "-w",
            "/data",
            WGCF_IMAGE,
            action,
        ]
    )
    return command


def run_in_terminal(stdscr, title, command):
    curses.def_prog_mode()
    curses.endwin()
    try:
        print(f"\n=== {title} ===")
        print("$ " + shlex.join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT)
        print(f"\n退出码：{result.returncode}")
        input("按 Enter 返回 TUI...")
        return result.returncode == 0
    finally:
        curses.reset_prog_mode()
        curses.curs_set(0)
        stdscr.refresh()


def run_wgcf_setup(stdscr):
    ensure_docker()
    account = WGCF / "wgcf-account.toml"
    profile = WGCF / "wgcf-profile.conf"
    if not account.exists():
        if not confirm(
            stdscr,
            "wgcf 注册会要求你在原始终端亲自同意 Cloudflare WARP 条款。继续？",
        ):
            return False
        if not run_in_terminal(
            stdscr, "初始化 WARP 账号", wgcf_command("register", True)
        ):
            raise RuntimeError("wgcf register 失败")
    if not account.exists():
        raise RuntimeError("未生成 wgcf-account.toml，无法继续")
    if not run_in_terminal(stdscr, "生成 WARP profile", wgcf_command("generate")):
        raise RuntimeError("wgcf generate 失败")
    for path in (account, profile):
        if path.exists():
            os.chmod(path, 0o600)
    parse_profile(profile)
    return True


def fetch_releases(limit):
    releases = []
    page = 1
    while len(releases) < limit:
        query = urlencode({"per_page": 100, "page": page})
        request = Request(
            f"{RELEASES_URL}?{query}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "sing-quota-builder",
            },
        )
        try:
            with urlopen(request, timeout=10) as response:
                page_releases = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            raise RuntimeError(f"GitHub API 请求失败：HTTP {error.code}") from error
        except (URLError, TimeoutError, OSError) as error:
            raise RuntimeError(f"无法访问 GitHub API：{error}") from error
        if not isinstance(page_releases, list):
            raise RuntimeError("GitHub API 返回的数据格式不正确")
        for release in page_releases:
            tag = release.get("tag_name", "")
            if (
                not release.get("draft")
                and not release.get("prerelease")
                and VERSION_PATTERN.fullmatch(tag)
            ):
                releases.append(release)
        if len(page_releases) < 100:
            break
        page += 1
    releases.sort(
        key=lambda release: (
            release.get("published_at") or release.get("created_at") or ""
        ),
        reverse=True,
    )
    return releases[:limit]


def image_exists(image):
    return (
        subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def active_singbox_image():
    image = text(
        load_slices()["runtime"].get("sing_box_image", ""),
        "当前 sing-box 镜像",
    )
    ensure_docker()
    if not image_exists(image):
        raise RuntimeError(f"当前 sing-box 镜像不存在：{image}")
    return image


def singbox_generate(*arguments):
    image = active_singbox_image()
    result = subprocess.run(
        ["docker", "run", "--rm", image, "generate", *arguments],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or "未知错误"
        raise RuntimeError(f"sing-box generate {' '.join(arguments)} 失败：{detail}")
    output = result.stdout.strip()
    if not output:
        raise RuntimeError(f"sing-box generate {' '.join(arguments)} 没有输出")
    return output


def shadowsocks_password_size(method):
    sizes = {
        "2022-blake3-aes-128-gcm": 16,
        "2022-blake3-aes-256-gcm": 32,
        "2022-blake3-chacha20-poly1305": 32,
    }
    try:
        return sizes[method]
    except KeyError as error:
        raise RuntimeError(f"不支持自动生成密码的 Shadowsocks 方法：{method}") from error


def generate_shadowsocks_password(method):
    return singbox_generate("rand", "--base64", str(shadowsocks_password_size(method))).splitlines()[-1]


def generate_reality_keypair():
    values = {}
    for line in singbox_generate("reality-keypair").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key.strip().lower()] = value.strip()
    private_key = values.get("privatekey") or values.get("private_key")
    public_key = values.get("publickey") or values.get("public_key")
    if not private_key or not public_key:
        raise RuntimeError("无法解析 sing-box 生成的 Reality 密钥对")
    return private_key, public_key


def set_active_singbox_image(image):
    runtime = load_slices()["runtime"]
    runtime["sing_box_image"] = image
    save_slice("runtime", runtime)


def build_images(stdscr, version, rebuild=False):
    ensure_docker()
    if not VERSION_PATTERN.fullmatch(version):
        raise RuntimeError(f"版本格式无效：{version}")
    version = version if version.startswith("v") else f"v{version}"
    for target, image_name in IMAGE_NAMES.items():
        image = f"{image_name}:{version}"
        if not rebuild and image_exists(image):
            show_message(stdscr, "镜像已存在", f"跳过：{image}")
            continue
        command = [
            "docker",
            "build",
            "--file",
            "Dockerfile",
            "--target",
            target,
            "--build-arg",
            f"SING_BOX_VERSION={version}",
            "--tag",
            image,
            ".",
        ]
        if not run_in_terminal(stdscr, f"构建 {image}", command):
            raise RuntimeError(f"构建失败：{image}")
    active_image = f"{IMAGE_NAMES['sing-box']}:{version}"
    set_active_singbox_image(active_image)
    show_message(stdscr, "构建完成", f"当前 sing-box 镜像：{active_image}")


def safe_addstr(stdscr, row, column, content, attribute=0):
    height, width = stdscr.getmaxyx()
    if 0 <= row < height and column < width:
        try:
            stdscr.addnstr(
                row, column, str(content), max(width - column - 1, 0), attribute
            )
        except curses.error:
            pass


def menu(stdscr, title, items, hint="Esc 返回", current=0):
    current = max(0, min(current, len(items) - 1))
    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
        safe_addstr(stdscr, 1, 0, hint, curses.A_DIM)
        visible = max(1, height - 4)
        start = min(max(0, current - visible + 1), max(0, len(items) - visible))
        for row, index in enumerate(
            range(start, min(start + visible, len(items))), start=3
        ):
            attribute = curses.A_REVERSE if index == current else 0
            safe_addstr(
                stdscr,
                row,
                0,
                f" {'›' if index == current else ' '} {index + 1}. {items[index]}",
                attribute,
            )
        stdscr.refresh()
        key = stdscr.getch()
        if key in (curses.KEY_UP, ord("k")):
            current = (current - 1) % len(items)
        elif key in (curses.KEY_DOWN, ord("j")):
            current = (current + 1) % len(items)
        elif key in (10, 13, curses.KEY_ENTER):
            return current
        elif ord("1") <= key <= ord("9") and key - ord("1") < len(items):
            return key - ord("1")
        elif key in (27, ord("q")):
            return None


def show_message(stdscr, title, content):
    stdscr.erase()
    safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
    for row, line in enumerate(str(content).splitlines(), start=2):
        safe_addstr(stdscr, row, 0, line)
    safe_addstr(stdscr, stdscr.getmaxyx()[0] - 1, 0, "按任意键继续", curses.A_DIM)
    stdscr.refresh()
    stdscr.getch()


def wrap_text(content, width):
    wrapper = textwrap.TextWrapper(
        width=max(1, width),
        break_long_words=True,
        break_on_hyphens=False,
        replace_whitespace=False,
        drop_whitespace=False,
    )
    return [
        segment
        for line in str(content).splitlines() or [""]
        for segment in (wrapper.wrap(line) or [""])
    ]


def copy_original_text(content):
    encoded = base64.b64encode(str(content).encode()).decode()
    sys.stdout.write(f"\033]52;c;{encoded}\a")
    sys.stdout.flush()


def show_text(stdscr, title, content):
    offset = 0
    copied = False
    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        lines = wrap_text(content, width - 1)
        visible = max(1, height - 3)
        offset = min(offset, max(0, len(lines) - visible))
        safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
        for row, line in enumerate(lines[offset : offset + visible], start=2):
            safe_addstr(stdscr, row, 0, line)
        hint = "↑↓ 滚动，c 复制未换行原文，Esc 返回"
        if copied:
            hint = "已请求终端复制原文"
        safe_addstr(stdscr, height - 1, 0, hint, curses.A_DIM)
        stdscr.refresh()
        key = stdscr.getch()
        if key in (27, ord("q")):
            return
        if key in (curses.KEY_UP, ord("k")):
            offset = max(0, offset - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            offset = min(max(0, len(lines) - visible), offset + 1)
        elif key == ord("c"):
            copy_original_text(content)
            copied = True


def confirm(stdscr, question):
    return menu(stdscr, "确认", [question, "取消"], "Enter 确认，Esc 取消") == 0


def prompt(stdscr, title, label, value="", secret=False):
    buffer = list(str(value))
    while True:
        stdscr.erase()
        safe_addstr(stdscr, 0, 0, title, curses.A_BOLD)
        safe_addstr(stdscr, 2, 0, label)
        shown = "*" * len(buffer) if secret else "".join(buffer)
        safe_addstr(stdscr, 4, 0, f"> {shown}")
        safe_addstr(stdscr, 6, 0, "Enter 保存，Esc 取消，Ctrl+U 清空，Backspace 删除", curses.A_DIM)
        stdscr.refresh()
        try:
            key = stdscr.get_wch()
        except curses.error:
            continue
        if key in ("\n", "\r"):
            return "".join(buffer)
        if key == "\x1b":
            return None
        if key == "\x15":
            buffer.clear()
        elif key in ("\x08", "\x7f") or key == curses.KEY_BACKSPACE:
            if buffer:
                buffer.pop()
        elif isinstance(key, str) and key.isprintable():
            buffer.append(key)


def edit_text(stdscr, title, settings, key, label, secret=False):
    value = prompt(stdscr, title, label, settings.get(key, ""), secret)
    if value is not None:
        settings[key] = value
        return True
    return False


def edit_integer(stdscr, title, settings, key, label):
    value = prompt(stdscr, title, label, settings.get(key, ""))
    if value is None:
        return False
    try:
        settings[key] = port(int(value), label)
    except (ValueError, RuntimeError) as error:
        show_message(stdscr, "输入无效", error)
        return False
    return True


def edit_quota_limit(stdscr, settings):
    value = prompt(stdscr, "流量额度", "额度（GiB，0 表示不限）", settings.get("limit_gb", 0))
    if value is None:
        return
    try:
        settings["limit_gb"] = quota_limit(float(value))
    except (ValueError, RuntimeError) as error:
        show_message(stdscr, "输入无效", error)


def edit_reset_day(stdscr, settings):
    value = prompt(stdscr, "重置日期", "每月重置日（0=不自动重置，1-31）", settings.get("reset_day", 0))
    if value is None:
        return
    try:
        settings["reset_day"] = reset_day(int(value))
    except (ValueError, RuntimeError) as error:
        show_message(stdscr, "输入无效", error)


def edit_log(stdscr):
    settings = load_slices()["log"]
    while True:
        runtime = load_slices()["runtime"]
        choice = menu(
            stdscr,
            "基础设置",
            [
                f"日志等级：{settings.get('level', '')}",
                f"日志时间戳：{'[x]' if settings.get('timestamp') else '[ ]'}",
                f"公网 IPv4：{runtime.get('public_ipv4') or '未获取'}",
                f"公网 IPv6：{runtime.get('public_ipv6') or '未获取'}",
                "返回",
            ],
        )
        if choice in (None, 4):
            save_slice("log", settings)
            return
        if choice == 0:
            index = menu(stdscr, "选择日志等级", ["debug", "info", "warn", "error"])
            if index is not None:
                settings["level"] = ["debug", "info", "warn", "error"][index]
        elif choice == 1:
            settings["timestamp"] = not bool(settings.get("timestamp"))


def generated_value(*arguments):
    return singbox_generate(*arguments).splitlines()[-1].strip()


def add_global_user(stdscr, users):
    name = prompt(stdscr, "新增全局用户", "用户名")
    if name is None:
        return
    name = text(name, "用户名")
    if any(user.get("name") == name for user in users):
        raise RuntimeError(f"用户名已存在：{name}")
    values = load_slices()
    materialize_generated_defaults(values)
    method = values["shadowsocks"].get("method", "")
    users.append(
        {
            "name": name,
            "uuid": generated_value("uuid"),
            "shadowsocks_password": generate_shadowsocks_password(method),
            "limit_gb": 0,
            "reset_day": 0,
        }
    )
    show_message(stdscr, "用户已添加", f"已为 {name} 生成 VLESS UUID 与 Shadowsocks 密码。")


def edit_global_users(stdscr):
    users = load_slices()["users"]
    while True:
        items = [user.get("name") or "未命名用户" for user in users]
        items.extend(["新增用户（使用当前 sing-box 镜像生成凭据）", "返回"])
        choice = menu(stdscr, "全局用户管理", items)
        if choice is None or choice == len(users) + 1:
            save_slice("users", users)
            return
        if choice == len(users):
            add_global_user(stdscr, users)
            save_slice("users", users)
            continue
        user = users[choice]
        while True:
            action = menu(
                stdscr,
                f"用户：{user.get('name') or '未命名'}",
                [
                    f"名称：{user.get('name', '')}",
                    "重新生成 VLESS UUID",
                    "重新生成 Shadowsocks 密码",
                    f"流量额度：{user.get('limit_gb', 0)} GiB",
                    f"每月重置日：{user.get('reset_day', 0)}",
                    "查看节点链接",
                    "删除此用户",
                    "返回",
                ],
            )
            if action is None or action == 7:
                break
            if action == 0:
                name = prompt(stdscr, "编辑用户", "用户名", user.get("name", ""))
                if name is not None:
                    name = text(name, "用户名")
                    if any(
                        item is not user and item.get("name") == name for item in users
                    ):
                        show_message(stdscr, "无法保存", f"用户名已存在：{name}")
                    else:
                        user["name"] = name
            elif action == 1:
                user["uuid"] = generated_value("uuid")
                show_message(stdscr, "UUID 已更新", "已通过当前 sing-box 镜像重新生成。")
            elif action == 2:
                method = load_slices()["shadowsocks"].get("method", "")
                user["shadowsocks_password"] = generate_shadowsocks_password(method)
                show_message(stdscr, "Shadowsocks 密码已更新", "已通过当前 sing-box 镜像重新生成。")
            elif action == 3:
                edit_quota_limit(stdscr, user)
            elif action == 4:
                edit_reset_day(stdscr, user)
            elif action == 5:
                try:
                    show_text(
                        stdscr,
                        f"{user.get('name') or '用户'} 的节点链接",
                        node_links(user),
                    )
                except RuntimeError as error:
                    show_message(stdscr, "无法生成链接", error)
            elif confirm(stdscr, f"从所有节点删除用户 {user.get('name')}？"):
                users.pop(choice)
                break
            save_slice("users", users)


def quota_usage_menu(stdscr):
    users = load_slices()["users"]
    while True:
        items = ["查看所有用户用量"]
        items.extend(f"手动清零：{user.get('name', '')}" for user in users)
        items.append("返回")
        choice = menu(stdscr, "额度与用量", items)
        if choice is None or choice == len(items) - 1:
            return
        try:
            ensure_docker()
            if choice == 0:
                command = [
                    "docker",
                    "compose",
                    "exec",
                    "quota-manager",
                    "python3",
                    "/app/quota.py",
                    "status",
                ]
                title = "查看用户用量"
            else:
                user = users[choice - 1]
                name = text(user.get("name", ""), "用户名")
                if not confirm(stdscr, f"清零 {name} 的用量并解除自动封禁？"):
                    continue
                command = [
                    "docker",
                    "compose",
                    "exec",
                    "quota-manager",
                    "python3",
                    "/app/quota.py",
                    "reset",
                    name,
                ]
                title = f"清零 {name} 的用量"
            if not run_in_terminal(stdscr, title, command):
                show_message(stdscr, "额度操作失败", "docker compose 命令返回非零退出码。")
        except RuntimeError as error:
            show_message(stdscr, "额度操作失败", error)


def edit_reality(stdscr, settings):
    tls = settings.setdefault(
        "tls", copy.deepcopy(DEFAULT_SLICES["vless-reality"]["tls"])
    )
    reality = tls.setdefault(
        "reality", copy.deepcopy(DEFAULT_SLICES["vless-reality"]["tls"]["reality"])
    )
    handshake = reality.setdefault("handshake", {"server": "", "server_port": 443})
    while True:
        choice = menu(
            stdscr,
            "Reality 设置",
            [
                f"Server name：{tls.get('server_name', '')}",
                f"握手地址：{handshake.get('server', '')}",
                f"握手端口：{handshake.get('server_port', '')}",
                "Reality 密钥对：已生成"
                if reality.get("private_key") and reality.get("public_key")
                else "Reality 密钥对：未生成",
                "使用当前 sing-box 生成 Reality 密钥对",
                f"Short ID：{', '.join(reality.get('short_id', [])) or '未设置'}",
                "使用当前 sing-box 新增 Short ID",
                f"最大时间差：{reality.get('max_time_difference', '')}",
                "返回",
            ],
        )
        if choice in (None, 8):
            return
        if choice == 0:
            edit_text(stdscr, "Reality 设置", tls, "server_name", "Server name")
        elif choice == 1:
            edit_text(stdscr, "Reality 设置", handshake, "server", "握手地址")
        elif choice == 2:
            edit_integer(stdscr, "Reality 设置", handshake, "server_port", "握手端口")
        elif choice == 4:
            private_key, public_key = generate_reality_keypair()
            reality["private_key"] = private_key
            reality["public_key"] = public_key
            show_message(stdscr, "Reality 密钥对已生成", "私钥已保存；公钥将供后续客户端配置使用。")
        elif choice == 5:
            value = prompt(
                stdscr,
                "Reality 设置",
                "Short ID，多个值用英文逗号分隔",
                ", ".join(reality.get("short_id", [])),
            )
            if value is not None:
                reality["short_id"] = split_values(value)
        elif choice == 6:
            short_id = generated_value("rand", "--hex", "8")
            if short_id not in reality.setdefault("short_id", []):
                reality["short_id"].append(short_id)
            show_message(stdscr, "Short ID 已生成", "已通过当前 sing-box 镜像生成并加入列表。")
        elif choice == 7:
            edit_text(
                stdscr, "Reality 设置", reality, "max_time_difference", "最大时间差"
            )


def edit_vless(stdscr):
    settings = load_slices()["vless-reality"]
    while True:
        choice = menu(
            stdscr,
            "VLESS Reality 节点",
            [
                f"启用：{'[x]' if settings.get('enabled') else '[ ]'}",
                f"Tag：{settings.get('tag', '')}",
                f"监听地址：{settings.get('listen', '')}",
                f"监听端口：{settings.get('listen_port', '')}",
                f"所有用户 Flow：{settings.get('flow', '')}",
                "Reality 设置",
                "返回",
            ],
        )
        if choice in (None, 6):
            save_slice("vless-reality", settings)
            return
        if choice == 0:
            settings["enabled"] = not bool(settings.get("enabled"))
        elif choice == 1:
            edit_text(stdscr, "VLESS Reality", settings, "tag", "Tag")
        elif choice == 2:
            edit_text(stdscr, "VLESS Reality", settings, "listen", "监听地址")
        elif choice == 3:
            edit_integer(stdscr, "VLESS Reality", settings, "listen_port", "监听端口")
        elif choice == 4:
            edit_text(stdscr, "VLESS Reality", settings, "flow", "所有用户 Flow")
        else:
            edit_reality(stdscr, settings)
        save_slice("vless-reality", settings)


def edit_shadowsocks(stdscr):
    settings = load_slices()["shadowsocks"]
    while True:
        choice = menu(
            stdscr,
            "Shadowsocks 节点",
            [
                f"启用：{'[x]' if settings.get('enabled') else '[ ]'}",
                f"Tag：{settings.get('tag', '')}",
                f"监听地址：{settings.get('listen', '')}",
                f"监听端口：{settings.get('listen_port', '')}",
                f"加密方法：{settings.get('method', '')}",
                "服务端密码：已设置"
                if settings.get("password")
                else "服务端密码：未设置",
                "使用当前 sing-box 生成服务端密码",
                "返回",
            ],
        )
        if choice in (None, 7):
            save_slice("shadowsocks", settings)
            return
        if choice == 0:
            settings["enabled"] = not bool(settings.get("enabled"))
        elif choice == 1:
            edit_text(stdscr, "Shadowsocks", settings, "tag", "Tag")
        elif choice == 2:
            edit_text(stdscr, "Shadowsocks", settings, "listen", "监听地址")
        elif choice == 3:
            edit_integer(stdscr, "Shadowsocks", settings, "listen_port", "监听端口")
        elif choice == 4:
            edit_text(stdscr, "Shadowsocks", settings, "method", "加密方法")
        elif choice == 5:
            edit_text(stdscr, "Shadowsocks", settings, "password", "服务端密码", True)
        else:
            settings["password"] = generate_shadowsocks_password(
                settings.get("method", "")
            )
            show_message(stdscr, "服务端密码已生成", "已通过当前 sing-box 镜像生成。")
        save_slice("shadowsocks", settings)


def wireguard_status(settings):
    path = resolve_profile(settings.get("profile", ""))
    if not path.exists():
        return "未找到 profile"
    try:
        profile = parse_profile(path)
    except RuntimeError as error:
        return f"profile 无效：{error}"
    addresses = profile["address"]
    ipv4 = any(":" not in address.split("/", 1)[0] for address in addresses)
    ipv6 = any(":" in address.split("/", 1)[0] for address in addresses)
    reserved = "有" if "reserved" in profile["peer"] else "无"
    return f"profile 有效：IPv4={'有' if ipv4 else '无'}，IPv6={'有' if ipv6 else '无'}，Reserved={reserved}，MTU={profile['mtu']}"


def edit_wireguard(stdscr):
    settings = load_slices()["wireguard"]
    while True:
        choice = menu(
            stdscr,
            "WARP / WireGuard",
            [
                f"启用：{'[x]' if settings.get('enabled') else '[ ]'}",
                f"Tag：{settings.get('tag', '')}",
                f"Userspace WireGuard（system: false）：{'[x]' if not settings.get('system') else '[ ]'}",
                f"状态：{wireguard_status(settings)}",
                "初始化 / 更新 wgcf profile",
                "返回",
            ],
        )
        if choice in (None, 5):
            save_slice("wireguard", settings)
            return
        if choice == 0:
            settings["enabled"] = not bool(settings.get("enabled"))
        elif choice == 1:
            edit_text(stdscr, "WARP / WireGuard", settings, "tag", "Tag")
        elif choice == 2:
            settings["system"] = not bool(settings.get("system"))
        elif choice == 4:
            try:
                if run_wgcf_setup(stdscr):
                    show_message(stdscr, "wgcf 完成", wireguard_status(settings))
            except RuntimeError as error:
                show_message(stdscr, "wgcf 失败", error)
        save_slice("wireguard", settings)


def active_routing_tags(values):
    inputs = []
    targets = ["direct"]
    if values["vless-reality"].get("enabled"):
        inputs.append(values["vless-reality"].get("tag", ""))
    if values["shadowsocks"].get("enabled"):
        inputs.append(values["shadowsocks"].get("tag", ""))
    if values["wireguard"].get("enabled"):
        targets.append(values["wireguard"].get("tag", ""))
    return [tag for tag in inputs if tag], [tag for tag in targets if tag]


def edit_routing(stdscr):
    values = load_slices()
    settings = values["route"]
    inputs, targets = active_routing_tags(values)
    if not inputs:
        show_message(stdscr, "无法配置路由", "请先启用至少一个入站协议。")
        return
    while True:
        mappings = {
            item.get("inbound"): item.get("outbound")
            for item in settings.get("basic_rules", [])
            if isinstance(item, dict)
        }
        items = [
            f"{source} → {mappings.get(source, '使用最终出口')}" for source in inputs
        ]
        items.extend([f"最终出口：{settings.get('final', '')}", "返回"])
        choice = menu(stdscr, "路由规则", items, "Enter 为每个已启用入站选择目标")
        if choice is None or choice == len(items) - 1:
            save_slice("route", settings)
            return
        if choice == len(inputs):
            target_index = menu(stdscr, "选择最终出口", targets)
            if target_index is not None:
                settings["final"] = targets[target_index]
        else:
            source = inputs[choice]
            options = ["使用最终出口"] + targets
            current = mappings.get(source)
            selected = options.index(current) if current in options else 0
            target_index = menu(stdscr, f"{source} 的目标", options, current=selected)
            if target_index is not None:
                settings["basic_rules"] = [
                    rule
                    for rule in settings.get("basic_rules", [])
                    if rule.get("inbound") != source
                ]
                if target_index:
                    settings["basic_rules"].append(
                        {"inbound": source, "outbound": targets[target_index - 1]}
                    )
        save_slice("route", settings)


def preview_config(stdscr):
    try:
        values = load_slices()
        config = build_config(values)
        users = validate_global_users(
            values["users"],
            boolean(values["vless-reality"].get("enabled"), "VLESS enabled"),
            boolean(values["shadowsocks"].get("enabled"), "Shadowsocks enabled"),
        )
    except RuntimeError as error:
        show_message(stdscr, "无法预览", error)
        return
    show_text(
        stdscr,
        "最终配置与额度预览（敏感字段已隐藏）",
        json.dumps(
            {"config": redacted(config), "quotas": build_quotas(users)},
            ensure_ascii=False,
            indent=2,
        ),
    )


def generate_config(stdscr):
    try:
        write_generated()
    except RuntimeError as error:
        show_message(stdscr, "生成失败", error)
        return
    show_message(
        stdscr,
        "生成成功",
        "已通过当前 sing-box 镜像校验并写入：\n"
        f"- {CONFIG}\n"
        f"- {QUOTAS}\n"
        f"- {COMPOSE}\n"
        f"上一次配置备份：{BACKUP if BACKUP.exists() else '无'}",
    )


def choose_release(stdscr):
    releases = fetch_releases(10)
    if not releases:
        raise RuntimeError("没有找到 sing-box 稳定版本")
    items = []
    for release in releases:
        date = (release.get("published_at") or release.get("created_at") or "未知")[:10]
        items.append(f"{release['tag_name']}  {date}  {release.get('name') or ''}")
    choice = menu(stdscr, "选择 sing-box 稳定版本", items)
    return None if choice is None else releases[choice]["tag_name"]


def image_build_menu(stdscr):
    while True:
        active_image = load_slices()["runtime"].get("sing_box_image") or "未选择"
        choice = menu(
            stdscr,
            f"Sing Quota 镜像（当前：{active_image}）",
            [
                "构建最新稳定版",
                "选择稳定版本后构建",
                "强制重建指定稳定版本",
                "查看最新 10 个稳定版本",
                "返回",
            ],
        )
        if choice in (None, 4):
            return
        try:
            if choice == 0:
                version = fetch_releases(1)[0]["tag_name"]
                build_images(stdscr, version)
            elif choice in (1, 2):
                version = choose_release(stdscr)
                if version:
                    build_images(stdscr, version, choice == 2)
            else:
                releases = fetch_releases(10)
                content = "\n".join(
                    f"{release['tag_name']:<18} {(release.get('published_at') or '')[:10]}  {release.get('name') or ''}"
                    for release in releases
                )
                show_text(stdscr, "最新 10 个 sing-box 稳定版本", content)
        except RuntimeError as error:
            show_message(stdscr, "Docker 操作失败", error)


def tui(stdscr):
    curses.curs_set(0)
    stdscr.keypad(True)
    initialize_slices()
    while True:
        choice = menu(
            stdscr,
            "sing-quota",
            [
                "Sing Quota 镜像",
                "基础设置",
                "全局用户管理",
                "额度与用量",
                "WARP / WireGuard",
                "VLESS Reality 节点",
                "Shadowsocks 节点",
                "路由规则",
                "预览最终 config.json",
                "生成 config.json、quotas.json 与 compose.yml",
                "退出",
            ],
            "↑↓ 或数字键选择，Enter 确认，Esc 退出",
        )
        try:
            if choice in (None, 10):
                return
            if choice == 0:
                image_build_menu(stdscr)
            elif choice == 1:
                edit_log(stdscr)
            elif choice == 2:
                edit_global_users(stdscr)
            elif choice == 3:
                quota_usage_menu(stdscr)
            elif choice == 4:
                edit_wireguard(stdscr)
            elif choice == 5:
                edit_vless(stdscr)
            elif choice == 6:
                edit_shadowsocks(stdscr)
            elif choice == 7:
                edit_routing(stdscr)
            elif choice == 8:
                preview_config(stdscr)
            else:
                generate_config(stdscr)
        except RuntimeError as error:
            show_message(stdscr, "操作失败", error)


def self_check():
    with tempfile.TemporaryDirectory() as directory:
        profile = Path(directory) / "wgcf-profile.conf"
        profile.write_text(
            "[Interface]\n"
            "PrivateKey = private\n"
            "Address = 172.16.0.2/32, 2606:4700:110::2/128\n"
            "MTU = 1280\n"
            "[Peer]\n"
            "PublicKey = public\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = engage.cloudflareclient.com:2408\n",
            encoding="utf-8",
        )
        values = copy.deepcopy(DEFAULT_SLICES)
        values["wireguard"].update({"enabled": True, "profile": str(profile)})
        values["users"] = [
            {
                "name": "main",
                "uuid": "uuid",
                "shadowsocks_password": "user-password",
            }
        ]
        values["vless-reality"]["enabled"] = True
        values["vless-reality"]["tls"].update({"server_name": "example.com"})
        values["vless-reality"]["tls"]["reality"].update(
            {
                "private_key": "reality-private",
                "public_key": "reality-public",
                "short_id": ["abcdef"],
                "handshake": {"server": "example.com", "server_port": 443},
            }
        )
        values["shadowsocks"].update(
            {"enabled": True, "password": "server-password"}
        )
        values["runtime"].update(
            {"public_ipv4": "203.0.113.10", "public_ipv6": "2001:db8::10"}
        )
        values["route"]["basic_rules"] = [{"inbound": "ss-in", "outbound": "wg-out"}]
        config = build_config(values)
        users = validate_global_users(values["users"], True, True)
        quotas = build_quotas(users)
        links = "\n".join(
            link
            for host in public_hosts(values)
            for link in (
                vless_link(users[0], values, host),
                shadowsocks_link(users[0], values, host),
            )
        )
        compose = build_compose(
            values,
            "sing-quota-sing-box:v1.14.0",
            "sing-quota-manager:v1.14.0",
        )
        assert config["endpoints"][0]["address"] == [
            "172.16.0.2/32",
            "2606:4700:110::2/128",
        ]
        assert config["route"]["rules"][0]["outbound"] == "wg-out"
        assert config["experimental"]["v2ray_api"]["stats"]["users"] == ["main"]
        assert quotas == {"main": {"limit_gb": 0.0, "reset_day": 0}}
        assert "vless://uuid@203.0.113.10:8443?" in links
        assert "vless://uuid@[2001:db8::10]:8443?" in links
        assert "fp=random" in links and "headerType=none" in links
        assert "ss://" in links
        assert wrap_text("abcdef", 3) == ["abc", "def"]
        assert '"8388:8388/udp"' in compose
        assert compose.count("driver: local") == 2
        assert "quota-state:" not in compose
        assert len(config["inbounds"]) == 2
    print("self-check passed")


def main():
    parser = argparse.ArgumentParser(description="sing-quota Linux TUI 配置生成器")
    parser.add_argument("--init", action="store_true", help="仅创建缺失的配置切片")
    parser.add_argument(
        "--self-check", action="store_true", help="运行离线配置组装自检"
    )
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if args.init:
        created = initialize_slices()
        print("已创建：" + (", ".join(created) if created else "无，切片已存在"))
        return
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error("TUI 必须在交互式 Linux 终端中运行")
    curses.wrapper(tui)


if __name__ == "__main__":
    main()
