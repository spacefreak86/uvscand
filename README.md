# uvscand
A python daemon to perform virus scans with uvscan (McAfee) over TCP socket, mainly used in conjunction with the antivirus module of rspamd.

## Installation

```bash
git clone https://github.com/spacefreak86/uvscand
cd uvscand

# build and install uvscand package
python3 -m build
python3 -m pip install .

# copy config file
cp docs/uvscand.conf /etc/

# install systemd service
cat << 'EOF'>> /etc/systemd/system/uvscand.service
[Unit]
Description=uvscand Service
After=multi-user.target
[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/python3 /usr/local/bin/uvscand
[Install]
WantedBy=multi-user.target
EOF

systemctl restart uvscand
systemctl status uvscand
systemctl enable uvscand

cat <<'EOF' >>/etc/rspamd/local.d/antivirus.conf
uvscan {
  scan_mime_parts = true;
  scan_text_mime = true;
  scan_image_mime = true;
  type = "clamav";
  symbol = "MCAFEE_VIRUS";
  servers = "127.0.0.1:10060";
  action = "reject";
}
EOF
systemctl restart rspamd
```

## Developer information

Everyone who wants to improve or extend this project is very welcome.
