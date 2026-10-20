#!/usr/bin/env python3
"""Seam A 用的极简引导 DNS（#23）：对 *.<suffix> 的 A 查询回答固定地址，
AAAA 回空的 NOERROR，其余名字回 NXDOMAIN。

用法：bootstrap_dns.py <bind-ip> <port> <suffix> <answer-ipv4>
"""
import socket
import sys


def main() -> None:
    bind_ip, port, suffix, answer = sys.argv[1], int(sys.argv[2]), sys.argv[3].lower(), sys.argv[4]
    answer_bytes = socket.inet_aton(answer)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    print(f"bootstrap dns on {bind_ip}:{port} *.{suffix} -> {answer}", flush=True)
    while True:
        query, peer = sock.recvfrom(512)
        if len(query) < 12:
            continue
        pos, labels = 12, []
        while pos < len(query) and query[pos] != 0:
            length = query[pos]
            labels.append(query[pos + 1 : pos + 1 + length].decode(errors="replace"))
            pos += 1 + length
        qtype = int.from_bytes(query[pos + 1 : pos + 3], "big")
        question = query[12 : pos + 5]
        name = ".".join(labels).lower()
        ours = name == suffix or name.endswith("." + suffix)
        rcode = 0 if ours else 3
        answers = b""
        if ours and qtype == 1:
            answers = b"\xc0\x0c" + b"\x00\x01\x00\x01" + (60).to_bytes(4, "big") + b"\x00\x04" + answer_bytes
        header = (
            query[0:2]
            + bytes([0x81, 0x80 | rcode])
            + b"\x00\x01"
            + (1 if answers else 0).to_bytes(2, "big")
            + b"\x00\x00\x00\x00"
        )
        sock.sendto(header + question + answers, peer)
        print(f"{peer[0]} {name} type={qtype} rcode={rcode}", flush=True)


if __name__ == "__main__":
    main()
