#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    printf '%s\n' 'The Burp bridge installer requires macOS.' >&2
    exit 1
fi

module_root=$(CDPATH= cd "$(dirname "$0")" && pwd)
install_dir="$HOME/.local/bin"
launch_dir="$HOME/Library/LaunchAgents"
service_label="com.proxprox.burp-bridge"
service_target="gui/$(id -u)/$service_label"
agent_plist="$launch_dir/$service_label.plist"

mkdir -p "$install_dir" "$launch_dir" "$HOME/Library/Logs"
temp_binary=$(mktemp "$install_dir/proxprox-bridge.XXXXXX")
trap 'rm -f "$temp_binary"' EXIT
(cd "$module_root" && go build -o "$temp_binary" ./cmd/bridge)
chmod 755 "$temp_binary"
mv -f "$temp_binary" "$install_dir/proxprox-bridge"
trap - EXIT

temp_plist=$(mktemp "$launch_dir/$service_label.XXXXXX")
trap 'rm -f "$temp_plist"' EXIT
cat > "$temp_plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$service_label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$install_dir/proxprox-bridge</string>
        <string>-listen</string><string>127.0.0.1:18081</string>
        <string>-upstream</string><string>proxy.proxprox.spiizn.xyz:18443</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardErrorPath</key><string>$HOME/Library/Logs/proxprox-bridge.log</string>
</dict>
</plist>
EOF
plutil -lint "$temp_plist"
mv -f "$temp_plist" "$agent_plist"
trap - EXIT

if launchctl print "$service_target" >/dev/null 2>&1; then
    launchctl bootout "$service_target"
fi
launchctl bootstrap "gui/$(id -u)" "$agent_plist"
launchctl print "$service_target" >/dev/null
printf '%s\n' 'Burp bridge installed on 127.0.0.1:18081.'
