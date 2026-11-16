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

The API listens on `127.0.0.1:8000`, MCP on `127.0.0.1:8001/mcp`, and the proxy on `127.0.0.1:18080`. These ports are published only on localhost. The proxy requires username `proxy` and `PROXY_TOKEN` as its password. The API and MCP each require their own Bearer token.

```sh
set -a; . ./.env; set +a
curl -x http://127.0.0.1:18080 --proxy-user "proxy:$PROXY_TOKEN" https://example.com/
```

Traffic without a matching rule goes directly to its destination, as requested for this pipeline.

## Rules and precedence

A rule contains `pattern`, `program_slug`, `upstream`, and `vpn`. The last two fields are optional. `*.example.com` matches subdomains at any depth, but does not match `example.com` itself. An exact match takes precedence over a wildcard. Among wildcards, the longest suffix wins. Patterns must be globally unique so that routing is unambiguous. Domain names and slugs must be lowercase; exact IP addresses are also accepted.

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
2. For username and password authentication, add `auth-user-pass /vpn/auth.txt` to `client.ovpn`. Create `vpn/acme/auth.txt` with the username on the first line and password on the second, then run `chmod 600 vpn/acme/auth.txt`. If the VPN only uses the profile's certificates and keys, `auth.txt` is unnecessary.
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

The `vpn-yeswehack` service is already defined in `compose.yaml` and mounts `vpn/yeswehack/` at `/vpn`. Save the complete profile as `vpn/yeswehack/client.ovpn`. In that file, keep `auth SHA512` and change the bare `auth-user-pass` line to `auth-user-pass /vpn/auth.txt`. The inline `ca`, `cert`, `key`, and `tls-auth` blocks do not need separate files. Put your YesWeHack VPN username on the first line of `vpn/yeswehack/auth.txt` and its password on the second, then run `chmod 600 vpn/yeswehack/client.ovpn vpn/yeswehack/auth.txt` because the profile contains a private key.

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

Both control ports are available locally only. For an agent on another machine, use a tunnel or an authenticated TLS frontend and preserve access controls. If the frontend forwards a public hostname to MCP, add it to `MCP_ALLOWED_HOSTS` in `.env` (for example, `mcp.example.org,mcp.example.org:*`). For a browser client, also set `MCP_ALLOWED_ORIGINS` to the exact HTTPS origin and configure CORS on the frontend.
