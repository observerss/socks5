#!/usr/bin/env python
# -*- coding: utf-8 -*-
import struct
import logging
import argparse

from curio import run, socket, spawn, tcp_server


logging.basicConfig(level=logging.INFO)
SOCKS_VERSION = 5


class SocksProxy:
    def __init__(self, host, port, username, password, eip):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.eip = eip

    async def run_server(self):
        logging.info(f'Listening on {self.host}:{self.port}')
        await tcp_server(self.host, self.port, self.handle)

    async def handle(self, conn, addr):
        logging.info(f'Accepting connection from {addr}')

        # greeting header
        # read and unpack 2 bytes from a client
        header = await conn.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        # socks 5
        assert version == SOCKS_VERSION
        assert nmethods > 0

        # get available methods
        methods = await self.get_available_methods(conn, nmethods)

        # accept only USERNAME/PASSWORD auth
        if 2 not in set(methods):
            # close connection
            conn.close()
            return

        # send welcome message
        await conn.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

        if not await self.verify_credentials(conn):
            return

        # request
        version, cmd, _, address_type = struct.unpack("!BBBB", await conn.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(await conn.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = ord(await conn.recv(1)[0])
            address = await conn.recv(domain_length)

        port = struct.unpack('!H', await conn.recv(2))[0]

        # reply
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.eip != '0.0.0.0':
                    remote.bind((self.eip, 0))
                await remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info(f'Connected to {(address, port)}')
            else:
                conn.close()
                return

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,
                                addr, port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)

        await conn.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            job1 = await spawn(self.forward_tcp, conn, remote)
            job2 = await spawn(self.forward_tcp, remote, conn)

        await job1.join()
        await job2.join()
        await conn.close()

    async def get_available_methods(self, conn, n):
        methods = []
        for _ in range(n):
            methods.append(ord(await conn.recv(1)))
        return methods

    async def verify_credentials(self, conn):
        version = ord(await conn.recv(1))
        assert version == 1

        username_len = ord(await conn.recv(1))
        username = (await conn.recv(username_len)).decode('utf-8')

        password_len = ord(await conn.recv(1))
        password = (await conn.recv(password_len)).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            await conn.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        await conn.sendall(response)
        await conn.close()
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    async def forward_tcp(self, src, dst):
        while True:
            try:
                data = await src.recv(4096)
                await dst.sendall(data)
                if not data:
                    break
            except:
                logging.exception('foward interrupted')
                break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=11080, help='port, default is 11080')
    parser.add_argument('--username')
    parser.add_argument('--password')
    parser.add_argument('--eip', default='0.0.0.0', help='external ip to bind')
    args = parser.parse_args()
    sp = SocksProxy(args.host, args.port, args.username, args.password, args.eip)
    run(sp.run_server)


if __name__ == '__main__':
    main()
