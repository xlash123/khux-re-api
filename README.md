# KHUX API Reverse Engineering
This repo contains tools I've been using to successfully view and modify API traffic for KHUx/KHDR. I do not condone the use of my tools to hack or gain an unfair advantage in the game; these tools are only available to gain insight on how the game functions.

## How Does the API Work?
There are 2 main endpoints involved in the API: `api-s.kingdomhearts.com` and `psg.sqex-bridge.jp/native/session`. Upon startup, KHUx communicates using an HTTPS REST API and JSON payloads to the KH api to obtain some status and session information. Most of these payloads are compressed using gzip. Then KHUx obtains a `sharedSecurityKey` and more session cookies from sqex after sending its session info.

This `sharedSecurityKey` is then used to encrypt/decrypt the JSON payload using AES-256 CBC mode. The encryption process is as shown:

`Raw JSON --(base64 encode)--> --(AES encrypt)--> -->(base64 encode)--> final payload`

Decrypting the payload is the reverse:

`received payload --(base64 decode)--> --(AES decrypt)--> --(base64 decode)--> final payload`

## What Does the Tool Do?
At the moment, the tool will automatically decode the traffic and display it in console in human-readable form. There is also support for easy modification to the JSON payload going to/from KHUx. The tool will repackage the payload in the form that KHUx understands.

## How To Setup
(will expand later) DNS, point to computer running this tool. Use self-signed cert trusted on phone. Run as sudo or proxy with NGINX.