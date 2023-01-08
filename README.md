# uvscand
A python daemon to perform virus scans with uvscan (McAfee) over TCP socket, mainly used in conjunction with the antivirus module of rspamd.

## Developer information
Everyone who wants to improve or extend this project is very welcome.

### Installation
git clone https://github.com/spacefreak86/uvscand
cd uvscand
python3 setup.py build
python3 setup.py install

cp docs/uvscand.conf /etc/

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
