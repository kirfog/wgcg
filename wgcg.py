#!/usr/bin/env python3
import codecs
import ipaddress
from pathlib import Path

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

server_config_file = Path("server.conf")
server_private_file = Path("private.key")
server_public_file = Path("public.key")


def generate_keys():
    private_key = X25519PrivateKey.generate()
    bytes_ = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private = codecs.encode(bytes_, "base64").decode("utf8").strip()
    pubkey = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    public = codecs.encode(pubkey, "base64").decode("utf8").strip()
    return private, public


def create_server_config(server_address, server_endpoint):
    server_private, server_public = generate_keys()
    with open(server_private_file, "w") as f:
        f.write(server_private)
    with open(server_public_file, "w") as f:
        f.write(server_public)
    wgserver = f"""
    [Interface]
    # clients endpoint {server_endpoint[0]}:{server_endpoint[1]}
    PrivateKey = {server_private}
    Address = {server_address}/32
    """
    with open(server_config_file, "w") as f:
        f.write(wgserver)
    return server_public


def create_client_config(
    server_public, server_endpoint, client_name, client_address, client_net
):
    client_private, client_public = generate_keys()
    Path(client_name).mkdir(parents=True)
    client_config_file = Path(f"{client_name}/client.conf")
    client_private_file = Path(f"{client_name}/private.key")
    client_public_file = Path(f"{client_name}/public.key")
    client_config_qr = Path(f"{client_name}/client.png")
    with open(client_private_file, "a") as f:
        f.write(client_private)
    with open(client_public_file, "a") as f:
        f.write(client_public)

    wgserver = f"""
    [Peer]
    # name {client_name}
    PublicKey = {client_public}
    AllowedIPs = {client_address}/32
    PersistentKeepalive = 10
    """
    with open(server_config_file, "a") as f:
        f.write(wgserver)

    wgclient = f"""
    [Interface]
    PrivateKey = {client_private}
    Address = {client_address}/32

    [Peer]
    PublicKey = {server_public}
    Endpoint = {server_endpoint[0]}:{server_endpoint[1]}
    AllowedIPs = {client_net}
    PersistentKeepalive = 20
    """
    with open(client_config_file, "w") as f:
        f.write(wgclient)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(wgclient)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(client_config_qr)
    print(wgclient)
    print(qr.print_ascii(invert=True))


def get_server():
    if (
        server_config_file.is_file()
        and server_private_file.is_file()
        and server_public_file.is_file()
    ):
        with open(server_public_file, "r") as f:
            server_public = f.read()
        with open(server_config_file, "r") as f:
            server_config = f.read().splitlines()
        clients = [
            ipaddress.ip_address(x.strip().split(" = ")[1][:-3])
            for x in server_config
            if "AllowedIPs" in x
        ]
        server_endpoint = [
            x.strip().split()[3] for x in server_config if "clients endpoint" in x
        ][0]
        server_endpoint_address, _, server_endpoint_port = server_endpoint.rpartition(
            ":"
        )
        server_endpoint_address = ipaddress.ip_address(server_endpoint_address)
        server_address = [
            ipaddress.ip_address(x.strip().split(" = ")[1][:-3])
            for x in server_config
            if "Address" in x
        ][0]
    else:
        server_endpoint = input("server_endpoint '1.1.1.1:55588': ") or "1.1.1.1:55588"
        server_endpoint_address, _, server_endpoint_port = server_endpoint.rpartition(
            ":"
        )
        server_endpoint_address = ipaddress.ip_address(server_endpoint_address)
        server_address = ipaddress.ip_address(
            input("server_address '192.168.0.1': ") or "192.168.0.1"
        )
        server_public = create_server_config(
            server_address, (server_endpoint_address, server_endpoint_port)
        )
        clients = []
    return (
        server_public,
        server_address,
        (server_endpoint_address, server_endpoint_port),
        clients,
    )


def get_clients():
    with open(server_config_file, "r") as f:
        server_config = f.read().splitlines()
        print(server_config)


server_public, server_address, server_endpoint, clients = get_server()

if len(clients) < 253:
    client_name = input("client_name 'client': ") or "client"
    client_address = server_address + len(clients) + 1
    client_net = input("server_net '0.0.0.0/0': ") or "0.0.0.0/0"
    client_net = f"{server_address},{client_net}"
    client_config_file = Path(f"{client_name}/client.conf")
    create_client_config(
        server_public, server_endpoint, client_name, client_address, client_net
    )
else:
    print(f"too many clients {server_address}")
