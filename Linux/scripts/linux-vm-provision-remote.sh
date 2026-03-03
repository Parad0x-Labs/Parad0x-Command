#!/bin/bash
set -euo pipefail

install -d -o ubuntu -g ubuntu /home/ubuntu/.vnc
cat >/home/ubuntu/.vnc/xstartup <<'EOF'
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XDG_SESSION_TYPE=x11
if command -v dbus-launch >/dev/null 2>&1; then
  exec dbus-launch --exit-with-session sh -lc '
    xfwm4 --compositor=off &
    xterm -geometry 140x38+20+20 -ls -title "Linux VM Shell" &
    while true; do sleep 3600; done
  '
fi
exec sh -lc '
  xfwm4 --compositor=off &
  xterm -geometry 140x38+20+20 -ls -title "Linux VM Shell" &
  while true; do sleep 3600; done
'
EOF
chmod +x /home/ubuntu/.vnc/xstartup
chown -R ubuntu:ubuntu /home/ubuntu/.vnc

sudo -u ubuntu -H bash -lc 'mkdir -p ~/.vnc && vncpasswd -f </home/ubuntu/vnc-password.txt >~/.vnc/passwd && chmod 600 ~/.vnc/passwd'

cat >/usr/local/bin/linux-browser-lab-vnc-start.sh <<'EOF'
#!/bin/bash
set -euo pipefail

sudo -u ubuntu -H vncserver -kill :1 >/dev/null 2>&1 || true
pkill -u ubuntu -f '/usr/bin/Xtigervnc :1' >/dev/null 2>&1 || true
rm -f /tmp/.X1-lock /tmp/.X11-unix/X1

sudo -u ubuntu -H bash -lc 'vncserver :1 -localhost no -geometry 1440x900 -depth 24 >/tmp/linux-browser-lab-vnc-start.log 2>&1 || true'

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
