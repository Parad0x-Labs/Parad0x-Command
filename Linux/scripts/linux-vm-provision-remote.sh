#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  autocutsel \
  dbus-x11 \
  firefox \
  novnc \
  xclip \
  python3-venv \
  tigervnc-standalone-server \
  tigervnc-tools \
  websockify \
  wmctrl \
  x11-utils \
  xdotool \
  xfce4 \
  xfce4-goodies \
  xfce4-terminal \
  xterm

install -d -o ubuntu -g ubuntu /home/ubuntu/.vnc
cat >/home/ubuntu/.vnc/xstartup <<'EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XDG_SESSION_TYPE=x11
export DESKTOP_SESSION=xfce
export XDG_CURRENT_DESKTOP=XFCE
# Clipboard sync helpers for VNC clients (Screen Sharing/noVNC).
if command -v vncconfig >/dev/null 2>&1; then
  vncconfig -nowin &
fi
if command -v autocutsel >/dev/null 2>&1; then
  autocutsel -selection CLIPBOARD -fork
  autocutsel -selection PRIMARY -fork
fi
if command -v dbus-launch >/dev/null 2>&1; then
  exec dbus-launch --exit-with-session startxfce4
fi
exec startxfce4
EOF
chmod +x /home/ubuntu/.vnc/xstartup
chown -R ubuntu:ubuntu /home/ubuntu/.vnc

sudo -u ubuntu -H bash -lc 'mkdir -p ~/.vnc && vncpasswd -f </home/ubuntu/vnc-password.txt >~/.vnc/passwd && chmod 600 ~/.vnc/passwd'

# Force XFCE browser helper to Firefox to avoid exo-open default-browser errors.
install -d -o ubuntu -g ubuntu /home/ubuntu/.config/xfce4
cat >/home/ubuntu/.config/xfce4/helpers.rc <<'EOF'
WebBrowser=firefox
MailReader=thunderbird
TerminalEmulator=xfce4-terminal
FileManager=thunar
EOF
chown -R ubuntu:ubuntu /home/ubuntu/.config/xfce4

# Pin the panel's Web Browser launcher to Firefox directly.
if [[ -f /home/ubuntu/.config/xfce4/panel/launcher-19/17725603943.desktop ]]; then
  sed -i 's|^Exec=.*|Exec=firefox %u|' /home/ubuntu/.config/xfce4/panel/launcher-19/17725603943.desktop
  chown ubuntu:ubuntu /home/ubuntu/.config/xfce4/panel/launcher-19/17725603943.desktop
fi

cat >/usr/local/bin/linux-browser-lab-vnc-start.sh <<'EOF'
#!/bin/bash
set -euo pipefail

sudo -u ubuntu -H vncserver -kill :1 >/dev/null 2>&1 || true
pkill -u ubuntu -f '/usr/bin/Xtigervnc :1' >/dev/null 2>&1 || true
rm -f /tmp/.X1-lock /tmp/.X11-unix/X1

sudo -u ubuntu -H bash -lc 'vncserver :1 -localhost no -geometry 1440x900 -depth 24 -AcceptCutText=1 -SendCutText=1 >/tmp/linux-browser-lab-vnc-start.log 2>&1 || true'

if pgrep -u ubuntu -f '/usr/bin/Xtigervnc :1' >/dev/null 2>&1; then
  exit 0
fi

cat /tmp/linux-browser-lab-vnc-start.log >&2 || true
exit 1
EOF
chmod +x /usr/local/bin/linux-browser-lab-vnc-start.sh

cat >/usr/local/bin/linux-browser-lab-vnc-stop.sh <<'EOF'
#!/bin/bash
set -euo pipefail

sudo -u ubuntu -H vncserver -kill :1 >/dev/null 2>&1 || true
pkill -u ubuntu -f '/usr/bin/Xtigervnc :1' >/dev/null 2>&1 || true
rm -f /tmp/.X1-lock /tmp/.X11-unix/X1
EOF
chmod +x /usr/local/bin/linux-browser-lab-vnc-stop.sh

cat >/etc/systemd/system/vncserver.service <<'EOF'
[Unit]
Description=TigerVNC server on display :1
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/linux-browser-lab-vnc-start.sh
ExecStop=/usr/local/bin/linux-browser-lab-vnc-stop.sh

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/novnc.service <<'EOF'
[Unit]
Description=noVNC web access
After=network.target vncserver.service
Requires=vncserver.service

[Service]
Type=simple
ExecStart=/usr/share/novnc/utils/novnc_proxy --listen 6080 --vnc localhost:5901
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vncserver.service novnc.service

if command -v snap >/dev/null 2>&1; then
  snap install chromium || true
fi

rm -f /home/ubuntu/vnc-password.txt
