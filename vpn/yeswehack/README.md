Place the complete YesWeHack profile here as client.ovpn. Change its bare
auth-user-pass directive to "auth-user-pass /vpn/auth.txt". Put the VPN username
and password on separate lines in auth.txt, then run chmod 600 on both files.
The profile's inline CA, certificate, key, and tls-auth blocks need no separate
files. This directory is mounted read-only at /vpn by the vpn-yeswehack service.
The profile and auth.txt are ignored by Git.
