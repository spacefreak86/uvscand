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
import re
import struct
import sys
import time

from subprocess import Popen, PIPE


uvscan_regex = re.compile(r"Found:?(?: the| potentially unwanted program| (?:virus|trojan) or variant)? (.+?)(?:\.| (?:virus |trojan )?)", re.MULTILINE)


async def uvscan_worker(queue):
    while True:
        job = await queue.get()
        if job is None:
            await queue.put(None)
            break
        uvscan, filename, cb = job
        proc = await asyncio.create_subprocess_exec(uvscan, "--secure", "--mime", "--noboot", "--panalyse", "--manalyse", "--timeout=15",  filename, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        if proc.returncode == 13:
            match = uvscan_regex.search(stdout.decode())
            name = match.group(1) if match else "UNKNOWN"
            result = "stream: {} FOUND".format(name)
        else:
            result = "stream: OK"
        cb(result)


class AIO(asyncio.Protocol):
    config = None
    queue = asyncio.Queue()
    separator = b"\x00"

    def __init__(self):
        if not AIO.config:
            raise RuntimeError("configuration not set")
        if not AIO.queue:
            raise RuntimeError("queue not set")
        self.logger = logging.getLogger(__name__)
        self.tmpfile = None

    def _send_response(self, response):
        response = response.encode() + AIO.separator
        self.logger.debug("{} sending response: {}".format(self.peer, response))
        self.transport.write(response)
        self.transport.close()


    def connection_made(self, transport):
        self.peer = transport.get_extra_info("peername")
        self.logger.info("new connection from {}".format(self.peer))
        self.transport = transport
        self.request_time = str(time.time())
        self.buffer = bytearray()
        self.data = bytearray()
        self.command = None
        self.length = None
        self.all_chunks = False
        self.completed = False

    def data_received(self, data):
        try:
            if self.all_chunks:
                self.logger.warning("{} received {} bytes of garbage after last chunk".format(self.peer, len(data)))
                return
            self.logger.debug("{} received {} bytes".format(self.peer, len(data)))
            self.buffer.extend(data)

            if not self.command:
                if len(self.buffer) < 10:
                    return
                if self.buffer[0] != ord(b"z"):
                    raise RuntimeError("protocol error")
                pos = self.buffer.index(ord(AIO.separator))
                # parse command
                command = self.buffer[0:pos].decode()
                if command != "zINSTREAM":
                    raise RuntimeError("unknown command")
                self.command = command
                self.logger.debug("{} command is {}".format(self.peer, command))
                pos += 1
                self.buffer = self.buffer[pos:]
            if self.command:
                while True:
                    if not self.length:
                        if len(self.buffer) < 4:
                            break
                        self.length = struct.unpack(">I", self.buffer[0:4])[0]
                        self.buffer = self.buffer[4:]
                        if self.length == 0:
                            self.all_chunks = True
                            tmpfile = os.path.join(AIO.config["tmpdir"], "uvscan_{}_{}".format(self.request_time, str(self.peer[1])))
                            self.logger.debug("{} got last chunk, save data to {}".format(self.peer, tmpfile))
                            with open(tmpfile, "wb") as f:
                                self.tmpfile = tmpfile
                                f.write(self.data)
                            AIO.queue.put_nowait((AIO.config["uvscan_path"], tmpfile, self.process_uvscan_result))
                            self.logger.info("{} queued uvscan of {}, queue size is {}".format(self.peer, tmpfile, AIO.queue.qsize()))
                            break
                        self.logger.debug("{} got chunk size of {} bytes".format(self.peer, self.length))
                    else:
                        if len(self.buffer) < self.length:
                            self.logger.debug("{} got {} of {} bytes".format(self.peer, len(self.buffer), self.length))
                            break
                        self.logger.debug("{} chunk complete ({} bytes)".format(self.peer, self.length))
                        self.data.extend(self.buffer[0:self.length])
                        self.buffer = self.buffer[self.length:]
                        self.length = None

        except (RuntimeError, IndexError, IOError, struct.error) as e:
            self.logger.warning("{} warning: {}".format(self.peer, e))
            self._send_response(str(e))

    def process_uvscan_result(self, result):
        self.logger.info("{} received uvscan result of {}: {}".format(self.peer, self.tmpfile, result))
        self.completed = True
        self._send_response(result)

    def connection_lost(self, exc):
        if self.tmpfile:
            if not self.completed:
                self.logger.warning("{} client prematurely closed connection, removing {} from scan queue".format(self.peer, self.tmpfile))
                entries = []
                try:
                    for entry in iter(AIO.queue.get_nowait, None):
                        if not entry:
                            continue
                        if entry[1] != self.tmpfile:
                            entries.append(entry)
                except asyncio.QueueEmpty:
                    pass
                for entry in entries:
                    AIO.queue.put_nowait(entry)
            self.logger.debug("{} removing temporary file {}".format(self.peer, self.tmpfile))
            os.remove(self.tmpfile)
        self.logger.info("closed connection to {}".format(self.peer))


def main():
    "Run uvscand."
    # parse command line
    parser = argparse.ArgumentParser(description="uvscand daemon",
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=45, width=140))
    parser.add_argument("-c", "--config", help="List of config files to read.", nargs="+",
            default=["/etc/uvscand.conf"])
    parser.add_argument("-m", "--maxprocs", help="Maximum number of parallel scan processes.",
            type=int, default=8)
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
    sysloghandler = logging.handlers.SysLogHandler(address="/dev/log")
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

    if not args.debug:
        # set loglevel according to config
        stdouthandler.setLevel(int(config["loglevel"]))
        sysloghandler.setLevel(int(config["loglevel"]))

    # check if uvscan binary exists and is executable
    if not os.path.isfile(config["uvscan_path"]) or not os.access(config["uvscan_path"], os.X_OK):
        logger.error("uvscan binary '{}' does not exist or is not executable".format(config["uvscan_path"]))
        sys.exit(1)

    # setup protocol
    AIO.config = config

    # start uvscan workers
    loop = asyncio.get_event_loop()
    workers = [loop.create_task(uvscan_worker(AIO.queue)) for _ in range(args.maxprocs)]

    # start server
    coro = loop.create_server(AIO, config["bind_address"], config["bind_port"])
    server = loop.run_until_complete(coro)
    logger.info("uvscand started")

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    # close server
    server.close()
    loop.run_until_complete(server.wait_closed())

    # shutdown uvscan workers
    loop.run_until_complete(AIO.queue.put(None))
    loop.run_until_complete(asyncio.wait(workers))
    loop.close()
    logger.info("uvscand stopped")


if __name__ == "__main__":
    main()
