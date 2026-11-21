"""Discord CDN media helpers — shared by auth.py and dashboard_api.py."""
import os
import time

import httpx

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

_AV_CACHE: dict[int, tuple[float, str | None, str | None]] = {}
_AV_TTL_OK = 600
_AV_TTL_MISS = 60

_GUILD_CACHE: dict[int, tuple[float, str | None, str | None]] = {}
_GUILD_TTL_OK = 3600
_GUILD_TTL_MISS = 300


def _cdn_avatar(discord_id, avatar_hash):
    if not discord_id or not avatar_hash:
        return None
    ext = "gif" if avatar_hash.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.{ext}?size=128"


def _cdn_icon(guild_id, icon_hash):
    if not guild_id or not icon_hash:
        return None
    ext = "gif" if icon_hash.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/icons/{guild_id}/{icon_hash}.{ext}?size=128"


async def fetch_discord_user(discord_id):
    """Best-effort pfp lookup via bot token, memoised. Returns (username, avatar_url)."""
    if not BOT_TOKEN or not discord_id:
        return (None, None)
    try:
        did = int(discord_id)
    except (TypeError, ValueError):
        return (None, None)

    hit = _AV_CACHE.get(did)
    if hit:
        age = time.time() - hit[0]
        if (hit[1] or hit[2]) and age < _AV_TTL_OK:
            return (hit[1], hit[2])
        if not (hit[1] or hit[2]) and age < _AV_TTL_MISS:
            return (None, None)

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://discord.com/api/v10/users/{did}",
                headers={"Authorization": f"Bot {BOT_TOKEN}"},
            )
            if r.status_code != 200:
                _AV_CACHE[did] = (time.time(), None, None)
                return (None, None)
            u = r.json()
            name = u.get("username")
            av = _cdn_avatar(u.get("id"), u.get("avatar"))
            _AV_CACHE[did] = (time.time(), name, av)
            return (name, av)
    except Exception:
        _AV_CACHE[did] = (time.time(), None, None)
        return (None, None)


async def fetch_guild_media(guild_id):
    """Best-effort guild name + icon via bot token, memoised. Returns (name, icon_url)."""
    if not BOT_TOKEN or not guild_id:
        return (None, None)
    try:
        gid = int(guild_id)
    except (TypeError, ValueError):
        return (None, None)

    hit = _GUILD_CACHE.get(gid)
    if hit:
        age = time.time() - hit[0]
        if (hit[1] or hit[2]) and age < _GUILD_TTL_OK:
            return (hit[1], hit[2])
        if not (hit[1] or hit[2]) and age < _GUILD_TTL_MISS:
            return (None, None)

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://discord.com/api/v10/guilds/{gid}",
                headers={"Authorization": f"Bot {BOT_TOKEN}"},
            )
            if r.status_code != 200:
                _GUILD_CACHE[gid] = (time.time(), None, None)
                return (None, None)
            g = r.json()
            name = g.get("name")
            icon = _cdn_icon(g.get("id"), g.get("icon"))
            _GUILD_CACHE[gid] = (time.time(), name, icon)
            return (name, icon)
    except Exception:
        _GUILD_CACHE[gid] = (time.time(), None, None)
        return (None, None)
