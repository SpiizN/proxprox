# Proxprox

Proxprox is an explicit HTTP proxy for bug bounty traffic. It forwards HTTP, WebSocket upgrades, and HTTPS CONNECT tunnels without decrypting TLS. A scope rule selects a direct connection, an upstream HTTP/HTTPS proxy, an OpenVPN gateway, or a VPN followed by an upstream proxy.

## Start the stack

Docker Compose on Linux is required. VPN containers also need `/dev/net/tun`. The default deployment does not need Caddy. Point `PROXY_ACME_HOST` at this server and allow inbound TCP 80 and `PROXY_HTTPS_PORT` (18443 by default). Proxprox serves the ACME HTTP challenge on port 80 and the authenticated HTTPS proxy on port 18443.

```sh
test -e .env || cp .env.example .env
# Replace API_TOKEN, PROXY_TOKEN, MCP_TOKEN, and GATEWAY_TOKEN in .env
# with four different secrets. Generate each with: openssl rand -hex 32
docker compose up -d
docker compose ps
```

Compose builds the app and MCP images locally by default. The [publish workflow](.github/workflows/publish-images.yaml) also publishes `ghcr.io/spiizn/proxprox` and `ghcr.io/spiizn/proxprox-mcp` for `linux/amd64` and `linux/arm64` on pushes to `main`. To deploy those images instead, log in to GHCR if they are private and set `PROXPROX_PULL_POLICY=always` in `.env`. Set `PROXPROX_IMAGE_TAG=sha-<full commit SHA>` to pin both images to one release.

| Service | Local address | Authentication |
| --- | --- | --- |
| HTTP proxy | `127.0.0.1:18080` | Basic: `proxy` / `PROXY_TOKEN` |
| API | `http://127.0.0.1:8000` | Bearer `API_TOKEN` |
| MCP | `http://127.0.0.1:8001/mcp` | Bearer `MCP_TOKEN` |
| HTTPS proxy | `proxy.proxprox.spiizn.xyz:18443` | Basic: `proxy` / `PROXY_TOKEN` |

The Go service lives in `proxprox/`, the MCP service in `mcp/`, and VPN profiles in `vpn/`. The API, MCP, and plain HTTP proxy ports bind to loopback. The HTTPS proxy is public; use its TLS endpoint for remote clients.

```sh
set -a; . ./.env; set +a
curl -x http://127.0.0.1:18080 --proxy-user "proxy:$PROXY_TOKEN" https://example.com/
```

A destination without a matching scope goes directly to the target.

## Configure scopes

Register upstreams and VPN gateways with the API before assigning their names to rules. The `program_slug` identifies the bug bounty program. Exact hosts beat wildcard rules; among wildcards, the longest suffix wins. `*.example.com` matches subdomains but not `example.com`. Patterns are globally unique.

```sh
set -a; . ./.env; set +a
curl -sS -X POST http://127.0.0.1:8000/v1/upstreams \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"proxy1","url":"http://1.1.1.1:3128"}'
curl -sS -X POST http://127.0.0.1:8000/v1/rules \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"program_slug":"example-program","pattern":"*.example.com","upstream":"proxy1"}'
curl -sS -G http://127.0.0.1:8000/v1/resolve \
  -H "Authorization: Bearer $API_TOKEN" --data-urlencode 'host=hello.example.com'
```

Use `http://user:password@host:port` or `https://user:password@host:port` for an authenticated upstream. URL-encode special characters in its credentials. API and MCP responses hide upstream credentials. The full URL is stored in `data/config.json`; protect this directory on the host.

| Operation | API |
| --- | --- |
| Full configuration without upstream credentials | `GET /v1/config` |
| Winning route for a host | `GET /v1/resolve?host=...` |
| List or create scopes | `GET/POST /v1/rules` |
| Replace or delete a scope | `PUT/DELETE /v1/rules/{id}` |
| List or create upstreams | `GET/POST /v1/upstreams` |
| Replace or delete an upstream | `PUT/DELETE /v1/upstreams/{name}` |
| List or create VPNs | `GET/POST /v1/vpns` |
| Replace or delete a VPN | `PUT/DELETE /v1/vpns/{name}` |

Filter rules with `GET /v1/rules?program_slug=...`. Replacing a rule requires all route fields. An upstream or VPN referenced by a rule cannot be deleted. Configuration is reloaded at startup; an invalid file stops startup.

## OpenVPN

The `vpn-yeswehack` service mounts `vpn/yeswehack/` at `/vpn`. Save the complete profile as `vpn/yeswehack/client.ovpn`. Keep its `auth SHA512` line. For username/password authentication, change `auth-user-pass` to `auth-user-pass /vpn/auth.txt`, then put the username and password on separate lines in `vpn/yeswehack/auth.txt`. Inline certificate and key blocks need no separate files.

```sh
sudo chgrp 0 vpn/yeswehack/client.ovpn vpn/yeswehack/auth.txt
chmod 640 vpn/yeswehack/client.ovpn vpn/yeswehack/auth.txt
docker compose --profile vpn-yeswehack up -d
docker compose --profile vpn-yeswehack ps
docker compose logs --tail=50 vpn-yeswehack
```

Once the VPN is healthy, register its gateway:

```sh
set -a; . ./.env; set +a
curl -sS -X POST http://127.0.0.1:8000/v1/vpns \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"yeswehack","gateway":"vpn-yeswehack:8081"}'
```

To add another VPN, create its own `vpn/<name>/` directory with `client.ovpn` and any files referenced by that profile. Apply the same private file permissions, then duplicate the `vpn-yeswehack` service in `compose.yaml`. Change the service/profile name, volume path, and DNS variable. Start that profile, then register `vpn-<name>:8081` through `POST /v1/vpns`. Do not publish gateway port 8081.

The gateway binds target connections to `tun0`. Set `VPN_YESWEHACK_DNS` only if the VPN provides a DNS server reachable through the tunnel. If a rule has both `vpn` and `upstream`, traffic follows client > VPN > upstream > target. If the VPN fails, that rule does not fall back to a direct route. VPN profiles and credentials are ignored by Git.

## MCP and optional Caddy

MCP exposes `add_scope`, `update_scope`, `remove_scope`, `list_scopes`, `resolve_scope`, and `get_configuration`. Agents use the MCP Bearer token; upstream and VPN administration remains on the API.

The default deployment uses only its own Docker network. To expose the API and MCP through an existing Caddy container, add these settings to `.env` before starting or updating Proxprox:

```dotenv
COMPOSE_FILE=compose.yaml:compose.caddy.yaml
CADDY_NETWORK=proxprox-proxy
```

The overlay requires that external Docker network to exist. Create it if needed with `docker network create proxprox-proxy`, then attach Caddy to it:

```yaml
services:
  caddy:
    networks:
      - proxprox-proxy

networks:
  proxprox-proxy:
    external: true
```

Add these Caddy routes:

```caddyfile
mcp.proxprox.spiizn.xyz {
    reverse_proxy proxprox-mcp:8001
}
api.proxprox.spiizn.xyz {
    reverse_proxy proxprox-api:8000
}
http://proxy.proxprox.spiizn.xyz {
    reverse_proxy proxprox-api:8082
}
```

Create DNS records for these names pointing to the VPS. Caddy needs public ports 80 and 443. The overlay removes Proxprox's host port 80 binding; Caddy forwards only the proxy hostname's ACME challenges to Proxprox. The HTTPS proxy itself stays on public TCP 18443. Check the combined configuration with `docker compose config --quiet`, then run `docker compose up -d`. This overlay uses Compose's `!override` tag; update Docker Compose if it cannot parse that tag.

Remote MCP: `https://mcp.proxprox.spiizn.xyz/mcp`. Remote API: `https://api.proxprox.spiizn.xyz`. If MCP uses another hostname, add it to `MCP_ALLOWED_HOSTS`.

```sh
curl --proxy https://proxy.proxprox.spiizn.xyz:18443 \
  --proxy-user "proxy:$PROXY_TOKEN" https://example.com/
```

## Burp Suite on macOS

Burp's upstream proxy setting expects a plain HTTP proxy. The local bridge accepts Burp's HTTP proxy traffic on loopback and connects to Proxprox over TLS:

```sh
./proxprox/install-bridge-macos.sh
```

In Burp Settings > Network > Connections > Upstream proxy servers, add destination `*`, host `127.0.0.1`, port `18081`, and Basic credentials `proxy` / `PROXY_TOKEN`. The installer creates a LaunchAgent and writes errors to `~/Library/Logs/proxprox-bridge.log`. Re-run it after changing the bridge code.
