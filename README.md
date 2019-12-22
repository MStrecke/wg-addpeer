# wg-addpeer

This utility creates keys and a configuration file for a new WireGuard peer in a client/server setting.
It displays the configuration as a QR code for easy setup of a mobile phone "client".
It also updates the "server" configuration.

The client files may be deleted once the phone is set up.

It currently only works for IPv4.

## Requirements

- python3
- wireguard
- qrencode (to display a QR code)

## Usage

Login as root into the server and go to the folder containing the server configuration (most likely `/etc/wireguard`).  The server configuration file is usually named `wg0.conf` or similar.

You can then add the peer `new_peer` with:

```
wg-addpeer.py wg0.conf new_peer --public_ip <server_pubic_ip>
```

Because the `public_ip` is needed in all peer configurations a *hidden* configuration option has been created to set this value.  In this case the option `--public_ip` can be omitted.

The optional switch `--keep_alive` lets you change the WireGuard peer option `PersistentKeepalive` from its default of 25 seconds to any other integer value.  If set to "0", this option is disabled.

The option `--dns X.X.X.X` inserts the DNS setting into the clients `[Interface]` configuration.

With the switch `--route_all` the value of `AllowedIPs` will be changed to `0.0.0.0/0`.

You can skip the display of the QR code with the switch `--noqr`.

## Workflow

- The scripts scans the server configuration file to infer the subnet used (it assumes a /24 subnet mask) and the public IP of the server.
- It scans all IPv4 addresses in the configuration file to find the largest one within that subnet. It takes the next one for the new peer.
- The public IP address of the server has to be specified
  - either on the command line or by the "hidden" configuration option
- The tool creates a private key, the public key and a preshared secret using WireGuard's `wg` utility.
  - These values are stored in a subdirectory with the name of the new peer.
- It then creates a standard WireGuard peer configuration which is also stored in that directory under the name `config.txt`.
- It adds an entry for this peer in the server configuration.
- If not disabled it displays the peer configuation as QR code which can be scanned by the mobile device.
- If necessary the peer configuration can be edited and then re-displayed using:

```bash
qrencode -t utf8 < config.txt
```

- The peer subdirectory and its content may be deleted after the configuration has been installed on the mobile device.

The peer configuration is not very large and its representation as QR code using UTF8 graphic characters usually fits a terminal screen.  Larger QR codes can be converted to an image using

```bash
qrencode -t png output.png < config.txt
```

and displayed with any picture viewer.


## Configurations

The aim is to create a peer configuration file that don't need tweaking so that you can use the QR code right away.

The structure of the configuration of a server and its clients is similar.

A sever only becomes a server by convention (because all the clients are contacting it and not vice verca).  The peer playing the role of a sever **must** however have a public IP and port under which it can be reached.

The `[Interface]` part of the server configuration has to be in place before this tool can be used.

```
[Interface]
Address = <internal ip of the server>/32
PrivateKey = <server's private key>
ListenPort = <listing port of the server, default 51820>
# public_ip = <public ip of the server>
```

The option `public_ip` is not part of the official spec and therefore is *hidden* in a comment (#).  The value could also be provided via the command line.

The following values are derived from this part of the server configuration:

- from `Address`: the /24 subnet used
- from `PrivateKey`: the server's public key for the peer configuration files can be calculated from this private key
- from `ListenPort` and `public_ip`: the server's public presence on the internet

The following data will be generated by the tool:

- a private key for the peer
- the public key will be derived from that
- a preshared secret for this server/client connection

### Server

For each new client `new_peer` the tool appends the following values to the server's configuration file:

```
[Peer]
PublicKey = <new_peer public key>
PresharedKey = <new_peer-server preshared secret>
AllowedIPs = <internal ip of the peer>/32
```

### Client

For the client the following configuration is created:

```
[Interface]
Address = <internal ip of the client>/32
PrivateKey = <client's private key>

[Peer]
PublicKey = <servers's public key>
PresharedKey = <new_peer-server preshared secret>
Endpoint = <server's public IP and port>
AllowedIPs = <server's internal ip>/32
PersistentKeepalive = 25
```

As mentioned above the values for `AllowedIPs` and `PersistentKeepalive` can be influenced by command line parameters.