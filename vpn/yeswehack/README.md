Place the complete YesWeHack profile here as client.ovpn. Change its bare
auth-user-pass directive to "auth-user-pass /vpn/auth.txt". Put the VPN username
and password on separate lines in auth.txt. The container runs as UID/GID 0
without permission-bypass capabilities. On the host, run
"sudo chgrp 0 vpn/yeswehack/client.ovpn vpn/yeswehack/auth.txt" and
"chmod 640 vpn/yeswehack/client.ovpn vpn/yeswehack/auth.txt" from the project
root so the container can read the files without exposing them to other users.
The profile's inline CA, certificate, key, and tls-auth blocks need no separate
files. This directory is mounted read-only at /vpn by the vpn-yeswehack service.
The profile and auth.txt are ignored by Git.
