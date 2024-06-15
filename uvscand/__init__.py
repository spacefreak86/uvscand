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


uvscan_regex = re.compile(r"Found:?(?: the| potentially unwanted program| (?:virus|trojan) or variant)? (.+?)(?:\.| (?:virus |trojan )?)", re.MULTILINE)


async def uvscan_worker(queue):
    while True:
        job = await queue.get()
        if job is None:
            await queue.put(None)
            break
        uvscan, filename, cb = job
        proc = await asyncio.create_subprocess_exec(uvscan, "--secure", "--mime", "--noboot", "--panalyse", "--manalyse", filename, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        if proc.returncode == 13:
            match = uvscan_regex.search(stdout.decode())
            name = match.group(1) if match else "UNKNOWN"
            result = f"stream: {name} FOUND"
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
        self.cancelled = False

    def _send_response(self, response):
        response = response.encode() + AIO.separator
        self.logger.debug(f"{self.peer} sending response: {response}")
        self.transport.write(response)
        self.transport.close()

    def connection_made(self, transport):
        self.peer = transport.get_extra_info("peername")
        self.logger.info(f"new connection from {self.peer}")
        self.transport = transport
        self.request_time = str(time.time())
        self.buffer = bytearray()
        self.data = bytearray()
        self.command = None
        self.length = None
        self.all_chunks = False

    def data_received(self, data):
        try:
            nbytes = len(data)
            if self.all_chunks:
                self.logger.warning(f"{self.peer} received {nbytes} bytes of garbage after last chunk")
                return
            self.logger.debug(f"{self.peer} received {nbytes} bytes")
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
                self.logger.debug(f"{self.peer} command is {command}")
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
                            suffix = str(self.peer[1])
                            tmpfile = os.path.join(AIO.config["tmpdir"], f"uvscan_{self.request_time}_{suffix}")
                            self.logger.debug(f"{self.peer} got last chunk, save data to {tmpfile}")
                            with open(tmpfile, "wb") as f:
                                self.tmpfile = tmpfile
                                f.write(self.data)
                            AIO.queue.put_nowait((AIO.config["uvscan_path"], tmpfile, self.process_uvscan_result))
                            queuesize = AIO.queue.qsize()
                            self.logger.info(f"{self.peer} queued uvscan of {tmpfile}, queue size is {queuesize}")
                            break
                        self.logger.debug(f"{self.peer} got chunk size of {self.length} bytes")
                    else:
                        if len(self.buffer) < self.length:
                            nbytes = len(self.buffer)
                            self.logger.debug(f"{self.peer} got {nbytes} of {self.length} bytes")
                            break
                        self.logger.debug(f"{self.peer} chunk complete ({self.length} bytes)")
                        self.data.extend(self.buffer[0:self.length])
                        self.buffer = self.buffer[self.length:]
                        self.length = None

        except (RuntimeError, IndexError, IOError, struct.error) as e:
            self.logger.warning(f"{self.peer} warning: {e}")
            self._send_response(str(e))

    def process_uvscan_result(self, result):
        self.logger.debug(f"{self.peer} removing temporary file {self.tmpfile}")
        os.remove(self.tmpfile)
        self.tmpfile = None
        if not self.cancelled:
            self.logger.info(f"{self.peer} received uvscan result of {self.tmpfile}: {result}")
            self._send_response(result)

    def connection_lost(self, exc):
        if self.tmpfile:
            entries = []
            try:
                for entry in iter(AIO.queue.get_nowait, None):
                    if not entry:
                        continue
                    if entry[1] != self.tmpfile:
                        entries.append(entry)
                    else:
                        self.cancelled = True
            except asyncio.QueueEmpty:
                pass
            for entry in entries:
                AIO.queue.put_nowait(entry)
            if self.cancelled:
                self.logger.warning(f"{self.peer} client prematurely closed connection, skipped scan of {self.tmpfile}")
                self.logger.debug(f"{self.peer} removing temporary file {self.tmpfile}")
                os.remove(self.tmpfile)
            else:
                self.logger.warning(f"{self.peer} client prematurely closed connection")
                self.cancelled = True

        else:
            self.logger.info(f"closed connection to {self.peer}")


def main():
    "Run uvscand."
    # parse command line
    parser = argparse.ArgumentParser(
            description="uvscand daemon",
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=45, width=140))
    parser.add_argument("-c", "--config", help="List of config files to read.", nargs="+", default=["/etc/uvscand.conf"])
    parser.add_argument("-m", "--maxprocs", help="Maximum number of parallel scan processes.", type=int, default=8)
    parser.add_argument("-d", "--debug", help="Log debugging messages.", action="store_true")
    args = parser.parse_args()

    # setup logging
    loglevel = logging.INFO
    logname = "uvscand"
    syslog_name = logname
    if args.debug:
        loglevel = logging.DEBUG
        logname = f"{logname}[%(name)s]"
        syslog_name = f"{syslog_name}: [%(name)s] %(levelname)s"

    root_logger = logging.getLogger()
    root_logger.setLevel(loglevel)

    # setup console log
    stdouthandler = logging.StreamHandler(sys.stdout)
    stdouthandler.setLevel(loglevel)
    formatter = logging.Formatter(f"%(asctime)s {logname}: [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    stdouthandler.setFormatter(formatter)
    root_logger.addHandler(stdouthandler)

    # setup syslog
    sysloghandler = logging.handlers.SysLogHandler(address="/dev/log")
    sysloghandler.setLevel(loglevel)
    formatter = logging.Formatter(f"{syslog_name}: %(message)s")
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
            logger.error(f"option '{option}' not present in config section 'uvscand'")
            sys.exit(1)

    if not args.debug:
        # set loglevel according to config
        stdouthandler.setLevel(int(config["loglevel"]))
        sysloghandler.setLevel(int(config["loglevel"]))

    # check if uvscan binary exists and is executable
    if not os.path.isfile(config["uvscan_path"]) or not os.access(config["uvscan_path"], os.X_OK):
        logger.error(f"uvscan binary '{config['uvscan_path']}' does not exist or is not executable")
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
