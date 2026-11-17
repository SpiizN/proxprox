# Proxprox

An explicit HTTP proxy for a bug bounty pipeline. It forwards HTTP requests, WebSocket upgrades, and HTTPS `CONNECT` tunnels without TLS interception. Rules associate a domain or IP address with a program slug, an HTTP/HTTPS upstream proxy, and optionally an OpenVPN container. The route is selected for each new connection.

## Getting started

Requirements: Docker Compose on Linux and `/dev/net/tun` for VPNs. Create `.env` if it does not already exist:

```sh
test -e .env || cp .env.example .env
```

For a new `.env`, replace the four placeholder secrets with distinct random values. For example, run `openssl rand -hex 32` for each secret. Then start the stack:

```sh
docker compose up -d --build
docker compose ps
```

The API listens on `127.0.0.1:8000`, MCP on `127.0.0.1:8001/mcp`, and the local HTTP proxy on `127.0.0.1:18080`. The public HTTPS proxy listens on port `18443` by default. The proxy requires username `proxy` and `PROXY_TOKEN` as its password. The API and MCP each require their own Bearer token.

```sh
set -a; . ./.env; set +a
curl -x http://127.0.0.1:18080 --proxy-user "proxy:$PROXY_TOKEN" https://example.com/
```

Traffic without a matching rule goes directly to its destination, as requested for this pipeline.

## Rules and precedence

A rule contains `pattern`, `program_slug`, `upstream`, and `vpn`. The last two fields are optional and must reference registered names, not URLs. Create upstreams and VPNs through the administrative API before referencing them in an API or MCP scope rule. `*.example.com` matches subdomains at any depth, but does not match `example.com` itself. An exact match takes precedence over a wildcard. Among wildcards, the longest suffix wins. Patterns must be globally unique so that routing is unambiguous. Domain names and slugs must be lowercase; exact IP addresses are also accepted.

The slug is returned by `/v1/resolve`, listed by `/v1/config`, and can filter `/v1/rules?program_slug=...`. It is also available through the MCP tools.

```sh
set -a; . ./.env; set +a

curl -sS -X POST http://127.0.0.1:8000/v1/upstreams \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"proxy1","url":"http://1.1.1.1:3128"}'

curl -sS -X POST http://127.0.0.1:8000/v1/upstreams \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"proxy2","url":"http://2.2.2.2:8080"}'

curl -sS -X POST http://127.0.0.1:8000/v1/rules \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"program_slug":"example-program","pattern":"*.example.com","upstream":"proxy1"}'

curl -sS -X POST http://127.0.0.1:8000/v1/rules \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"program_slug":"example-program","pattern":"hello.example.com","upstream":"proxy2"}'

curl -sS -G http://127.0.0.1:8000/v1/resolve \
  -H "Authorization: Bearer $API_TOKEN" --data-urlencode 'host=hello.example.com'
```

An upstream URL can be `http://user:password@host:port` or `https://user:password@host:port`. URL-encode special characters in the credentials. The API and MCP hide upstream credentials in their responses. Credentials are stored in `data/config.json`, with permissions `0600` inside the container. Protect the `data` directory on the host as well.

## OpenVPN

Each VPN container has its own Docker network namespace. Its gateway accepts only authenticated `CONNECT` requests using `GATEWAY_TOKEN`. It binds outbound target connections to `tun0` and refuses new connections if `tun0` is unavailable. OpenVPN supplies the routes; the gateway does not force a default route. If `VPN_DNS` is set for a container, its DNS queries use that server through `tun0`. If it is empty, the container's normal DNS resolver is used, which is useful for split-tunnel VPNs.

The `vpn/example/` directory and the `vpn-example` service in `compose.yaml` are only templates. Real VPN profiles do not have to go into `vpn/example/`. Give each VPN its own directory and Compose service. Configure a VPN DNS server only when that VPN provides one. For example:

| VPN | Host directory | Compose service and profile | DNS setting in `.env` | Registered gateway |
| --- | --- | --- | --- | --- |
| acme | `vpn/acme/` | `vpn-acme` | `VPN_ACME_DNS` | `vpn-acme:8081` |
| beta | `vpn/beta/` | `vpn-beta` | `VPN_BETA_DNS` | `vpn-beta:8081` |

To add `acme`:

1. Create `vpn/acme/`. Copy the profile to `vpn/acme/client.ovpn`, along with any files it references (`ca`, `cert`, `key`, `tls-auth`, `tls-crypt`, or `pkcs12`). Relative paths in the profile resolve from `/vpn`, which maps to `vpn/acme/` for this container. If the profile embeds its certificates and keys, no additional files are needed.
2. For username and password authentication, add `auth-user-pass /vpn/auth.txt` to `client.ovpn`. Create `vpn/acme/auth.txt` with the username on the first line and password on the second. The gateway runs as UID/GID 0 without permission-bypass capabilities. For host-owned files, give group 0 read access while keeping access denied to others: `sudo chgrp 0 vpn/acme/client.ovpn vpn/acme/auth.txt && chmod 640 vpn/acme/client.ovpn vpn/acme/auth.txt`. Apply the same group and mode to any other private files referenced by the profile. If the VPN only uses the profile's certificates and keys, `auth.txt` is unnecessary; omit it from the command.
3. Copy the `vpn-example` block in `compose.yaml` to a new `vpn-acme` block. In the copy, change the Compose profile to `vpn-acme`, the mount from `./vpn/example:/vpn:ro` to `./vpn/acme:/vpn:ro`, and `VPN_EXAMPLE_DNS` to `VPN_ACME_DNS`. Keep the `vpn-example` block as a template or remove it.
4. If this VPN provides a DNS server reachable through the tunnel, set `VPN_ACME_DNS` in `.env` to its IP address. Otherwise, leave it empty to use the container's normal resolver. Run `docker compose --profile vpn-acme up -d --build`, then check `docker compose ps` and `docker compose logs --tail=50 vpn-acme`.
5. Register the gateway through the API:

```sh
set -a; . ./.env; set +a
curl -sS -X POST http://127.0.0.1:8000/v1/vpns \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"acme","gateway":"vpn-acme:8081"}'
```

Repeat these steps for each VPN in a separate directory. Do not put OpenVPN credentials in `.env` or in a shell command that will remain in shell history. Each VPN container needs `/dev/net/tun` and `NET_ADMIN`. Do not publish the gateway port on the host.

Git ignores the VPN files in these directories, except their README files. A profile that requires interactive input, such as an MFA code on every connection, needs a noninteractive method provided by the VPN before it can run in this service.

A rule can specify `"vpn":"acme"` with or without an upstream. With both, traffic follows `client > VPN > upstream > destination`. If the VPN goes down, the rule fails; it does not fall back to a direct connection.

### YesWeHack profile

The `vpn-yeswehack` service is already defined in `compose.yaml` and mounts `vpn/yeswehack/` at `/vpn`. Save the complete profile as `vpn/yeswehack/client.ovpn`. In that file, keep `auth SHA512` and change the bare `auth-user-pass` line to `auth-user-pass /vpn/auth.txt`. The inline `ca`, `cert`, `key`, and `tls-auth` blocks do not need separate files. Put your YesWeHack VPN username on the first line of `vpn/yeswehack/auth.txt` and its password on the second. The profile contains a private key, so keep access restricted to its owner and the container's group: `sudo chgrp 0 vpn/yeswehack/client.ovpn vpn/yeswehack/auth.txt && chmod 640 vpn/yeswehack/client.ovpn vpn/yeswehack/auth.txt`.

YesWeHack uses split-tunnel routes for eligible scope IPs. Leave `VPN_YESWEHACK_DNS` empty unless YesWeHack supplies a DNS server reachable through the VPN. Start the service with `docker compose --profile vpn-yeswehack up -d --build`. After it is healthy, register `{"name":"yeswehack","gateway":"vpn-yeswehack:8081"}` through `POST /v1/vpns`. The VPN username and password come from your YesWeHack account by default; the platform also lets you configure a separate VPN password.

## API and MCP

| Operation | API |
| --- | --- |
| Configuration without secrets | `GET /v1/config` |
| Route for a host | `GET /v1/resolve?host=...` |
| List or add rules | `GET/POST /v1/rules` |
| Replace or delete a rule | `PUT/DELETE /v1/rules/{id}` |
| List or add upstreams | `GET/POST /v1/upstreams` |
| Replace or delete an upstream | `PUT/DELETE /v1/upstreams/{name}` |
| List or add VPNs | `GET/POST /v1/vpns` |
| Replace or delete a VPN | `PUT/DELETE /v1/vpns/{name}` |

Create and replace operations accept JSON. Replacing a rule requires all of its fields. An upstream or VPN cannot be deleted while a rule refers to it. Configuration persists in `data/config.json` and is reloaded at startup. An unknown or invalid format stops startup rather than discarding stored data.

MCP uses Streamable HTTP at `http://127.0.0.1:8001/mcp` with the `Authorization: Bearer <MCP_TOKEN>` header. It provides `add_scope`, `update_scope`, `remove_scope`, `list_scopes`, `resolve_scope`, and `get_configuration`. Agents can register and inspect scopes; upstream and VPN management remains on the administrative API.

The control ports are published on the host's loopback interface only. Containers on the `proxprox-proxy` network can also reach them. For a remote agent, use Caddy as described below or a tunnel. If a different public hostname is forwarded to MCP, add it to `MCP_ALLOWED_HOSTS` in `.env` (for example, `mcp.example.org,mcp.example.org:*`). For a browser client, also set `MCP_ALLOWED_ORIGINS` to the exact HTTPS origin and configure CORS on the frontend.

## Caddy

This Compose stack creates a Docker network named `proxprox-proxy`. The API and MCP services join it as `proxprox-api:8000` and `proxprox-mcp:8001`. VPN containers remain on the stack's default network. Connect a Caddy container from another Compose project to the existing network:

```yaml
services:
  caddy:
    networks:
      - proxprox-proxy

networks:
  proxprox-proxy:
    external: true
```

Add these site blocks to Caddy's configuration:

```caddyfile
mcp.proxprox.spiizn.xyz {
    reverse_proxy proxprox-mcp:8001
}

api.proxprox.spiizn.xyz {
    reverse_proxy proxprox-api:8000
}
```

Create DNS records for both names that point to the VPS, and make sure Caddy can receive traffic on ports 80 and 443. The MCP server accepts `mcp.proxprox.spiizn.xyz` as a Host header by default; `MCP_ALLOWED_HOSTS` can add or override public hostnames. The API and MCP still require their respective Bearer tokens over HTTPS. The MCP endpoint is `https://mcp.proxprox.spiizn.xyz/mcp`, and the API base URL is `https://api.proxprox.spiizn.xyz`.

## Public HTTPS proxy

Ensure `proxy.proxprox.spiizn.xyz` resolves to the VPS, using an `A` record or a `CNAME` to a host that resolves to the VPS. Set `PROXY_ACME_HOST` in `.env` if you use a different name. Allow inbound TCP 18443 on the VPS firewall, or set `PROXY_HTTPS_PORT` to another public port. The proxy obtains and renews its certificate using ACME HTTP-01; its certificate cache persists in `data/proxy-acme/`.

Add this HTTP-only site to the existing Caddyfile and reload Caddy. Caddy must be on the `proxprox-proxy` network and reachable on public TCP port 80:

```caddyfile
http://proxy.proxprox.spiizn.xyz {
    reverse_proxy proxprox-api:8082
}
```

This route only serves certificate challenges. Clients connect directly to the HTTPS proxy on port 18443, not to Caddy on port 443. A regular Caddy `reverse_proxy` site does not relay forward-proxy `CONNECT` tunnels. The local HTTP proxy remains bound to loopback for local tools.

After deploying the updated stack with `docker compose up -d --build`, test from another machine with a client that supports HTTPS proxies:

```sh
curl -v --proxy https://proxy.proxprox.spiizn.xyz:18443 \
  --proxy-user "proxy:$PROXY_TOKEN" https://example.com/
```

Set `PROXY_TOKEN` in the client environment without putting the token in shell history. Do not disable TLS certificate verification. The first connection may take longer while the certificate is issued. If certificate issuance fails, check the DNS record, port 80, the Caddy route, and the `app` container logs. A plain HTTP proxy on a public port would expose the Basic authentication credentials to network observers.

## Burp Suite

Burp's upstream proxy settings use an HTTP proxy host and port. On the Mac running Burp, install the local bridge once:

```sh
./scripts/install-burp-bridge-macos.sh
```

The installer builds `~/.local/bin/proxprox-bridge` and starts a macOS LaunchAgent that keeps it running after login. The bridge listens only on `127.0.0.1:18081`, verifies the public proxy's TLS certificate, and forwards all bytes to `proxy.proxprox.spiizn.xyz:18443`. It stores no proxy password. Re-run the installer after updating the bridge code. Logs are at `~/Library/Logs/proxprox-bridge.log`.

In Burp Suite, open Settings > Network > Connections > Upstream proxy servers and add a rule with destination host `*`, proxy host `127.0.0.1`, proxy port `18081`, Basic authentication, username `proxy`, and password `PROXY_TOKEN`. This is an upstream rule for Burp's outgoing requests; Burp's browser-facing proxy listener remains separate. Proxprox still chooses the VPN and upstream proxy from each destination's scope rule. Keep the VPS HTTP proxy bound to `127.0.0.1`; publishing it publicly would expose Basic authentication credentials before a target's HTTPS tunnel begins.
