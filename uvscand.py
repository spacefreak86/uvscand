#!/usr/bin/env python
#
# uvscand is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# uvscand is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with PyQuarantineMilter.  If not, see <http://www.gnu.org/licenses/>.
#

import argparse
import asyncio
import configparser
import logging
import logging.handlers
import os
import sys
import time

from subprocess import Popen, PIPE




class AIO(asyncio.Protocol):
    config = None

    def __init__(self):
        if not config:
            raise RuntimeError("configuration not set")
        self.logger = logging.getLogger(__name__)
        self.data = bytearray()

    def connection_made(self, transport):
        self.logger.debug("new connection from {}".format(peer))
        self.peer = transport.get_extra_info("peername")
        self.transport = transport
        self.request_time = str(time.time())

    def data_received(self, data):
        self.logger.debug("data received from {}".format(self.peer))
        self.data.extend(request)

    def eof_received(self):
        protocol_err = False
        proto_ck = str(self.data[0:2000])
        if "UVSCAND" in proto_ck:
            line = proto_ck[12:proto_ck.find("\\n\\n")]
            self.data = bytearray(self.data[59:len(self.data)])
            header_lines = olefy_line.split('\\n')
            for line in header_lines:
                if line == 'OLEFY/1.0':
                    olefy_headers['olefy'] = line
                elif line != '':
                    kv = line.split(': ')
                    if kv[0] != '' and kv[1] != '':
                        olefy_headers[kv[0]] = kv[1]
            logger.debug('olefy_headers: {}'.format(olefy_headers))
        else:
            olefy_protocol_err = True

        lid = 'Rspamd-ID' in olefy_headers and '<'+olefy_headers['Rspamd-ID'][:6]+'>' or '<>'

        tmp_file_name = olefy_tmp_dir+'/'+request_time+'.'+str(self.peer[1])
        self.logger.debug('{} {} choosen as tmp filename'.format(lid, tmp_file_name))

        self.logger.info('{} {} bytes (stream size)'.format(lid, self.data.__len__()))

        if olefy_protocol_err == True or olefy_headers['olefy'] != 'OLEFY/1.0':
            self.logger.error('Protocol ERROR: no OLEFY/1.0 found)')
            out = b'[ { "error": "Protocol error" } ]'
        elif 'Method' in olefy_headers:
            if olefy_headers['Method'] == 'oletools':
                out = oletools(self.data, tmp_file_name, lid)
        else:
            self.logger.error('Protocol ERROR: Method header not found')
            out = b'[ { "error": "Protocol error: Method header not found" } ]'

        self.transport.write(out)
        self.logger.info('{} response send: {!r}'.format(self.peer, out))
        self.transport.close()


def main():
    "Run uvscand."
    # parse command line
    parser = argparse.ArgumentParser(description="uvscand daemon",
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=45, width=140))
    parser.add_argument("-c", "--config", help="List of config files to read.", nargs="+",
            default=["/etc/uvscand.conf"])
    parser.add_argument("-d", "--debug", help="Log debugging messages.", action="store_true")
    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    logname = "uvscand"
    syslog_name = logname
    if args.debug:
        loglevel = logging.DEBUG
        logname = "{}[%(name)s]".format(logname)
        syslog_name = "{}: [%(name)s] %(levelname)s".format(syslog_name)

    root_logger = logging.getLogger()
    root_logger.setLevel(loglevel)

    # setup console log
    stdouthandler = logging.StreamHandler(sys.stdout)
    stdouthandler.setLevel(loglevel)
    formatter = logging.Formatter("%(asctime)s {}: [%(levelname)s] %(message)s".format(logname), datefmt="%Y-%m-%d %H:%M:%S")
    stdouthandler.setFormatter(formatter)
    root_logger.addHandler(stdouthandler)

    # setup syslog
    sysloghandler = logging.handlers.SysLogHandler(address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_MAIL)
    sysloghandler.setLevel(loglevel)
    formatter = logging.Formatter("{}: %(message)s".format(syslog_name))
    sysloghandler.setFormatter(formatter)
    root_logger.addHandler(sysloghandler)

    logger = logging.getLogger(__name__)

    # parse config file
    parser = configparser.ConfigParser()
    parser.read(args.config)

    # check config
    if "uvscand" not in parser.sections():
        logger.error("section 'uvscand' is missing in config file")
        sys.exit(1)
    config = dict(parser.items("uvscand"))
    for option in ["bind_address", "bind_port", "tmpdir", "uvscan_path", "loglevel"]:
        if option not in config.keys():
            logger.error("option '{}' not present in config section 'uvscand'".format(option))
            sys.exit(1)

    # check if uvscan binary exists and is executable
    if not os.path.isfile(config["uvscan_path"]) or not os.access(config["uvscan_path"], os.X_OK):
        logger.error("uvscan binary '{}' does not exist or is not executable".format(config["uvscan_path"]))
        sys.exit(1)

    loop = asyncio.get_event_loop()
    AIO.config = config
    coro = loop.create_server(AIO, config.listen_addr, config.listen_port)
    server = loop.run_until_complete(coro)
    logger.info("uvscand started")

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    logger.info("uvscand stopped")


if __name__ == "__main__":
    main()
