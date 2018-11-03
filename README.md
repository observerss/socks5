# socks5
an async socks server that can switch outgoing ip

- python 3.6+ only

```bash
python socks.py --help

usage: socks.py [-h] [--host HOST] [--port PORT] [--username USERNAME]
             [--password PASSWORD] [--eip EIP]

optional arguments:
  -h, --help           show this help message and exit
  --host HOST
  --port PORT          port, default is 11080
  --username USERNAME
  --password PASSWORD
  --eip EIP            external ip to bind
```
