# ckb-light-client-js

Web version of CKB LightClient, provide full APIs of CKB LightClient in browser.

## Usage

### Install this package
```
npm install ckb-light-client-js
```
### A piece of code
```js
import { LightClient, randomSecretKey } from "light-client-js";

const client = new LightClient();

const config = `
chain = "dev"

[store]
path = "data/store"

[network]
path = "data/network"

listen_addresses = ["/ip4/0.0.0.0/tcp/8110"]
### Specify the public and routable network addresses
# public_addresses = []

# Node connects to nodes listed here to discovery other peers when there's no local stored peers.
# When chain.spec is changed, this usually should also be changed to the bootnodes in the new chain.
bootnodes = [
    "/ip4/18.167.71.41/tcp/8115/ws/p2p/QmZ3g4ikFdUijFyQdDsuxnvMwgC4uMU4Ux8siwPGPxLnRC",
    # "/ip4/18.167.71.41/tcp/8115/wss/p2p/QmZ3g4ikFdUijFyQdDsuxnvMwgC4uMU4Ux8siwPGPxLnRC"
]


max_peers = 125
max_outbound_peers = 2
# 2 minutes
ping_interval_secs = 120
# 20 minutes
ping_timeout_secs = 1200
connect_outbound_interval_secs = 15
# If set to true, try to register upnp
upnp = false
# If set to true, network service will add discovered local address to peer store, it's helpful for private net development
discovery_local_address = false
# If set to true, random cleanup when there are too many inbound nodes
# Ensure that itself can continue to serve as a bootnode node
bootnode_mode = false

`

await client.start({ type: "TestNet", config }, randomSecretKey(), "info");
console.log(await client.getTipHeader())
```

### A more complex example

https://github.com/Officeyutong/ckb-light-client-wasm-demo

## Restrictions
- ckb-light-client-js only supports WebSocket over TLS peers on HTTPS sites. On HTTP sites, insecure WebSocket may be used.

- Due to the restrictions of browsers, you must set some headers properly. See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/SharedArrayBuffer#security_requirements for details. There are some configuration examples:

### nginx

```
    server {
        listen 5600;
        server_name localhost;
        root /root/ckb-light-client;
        location / {
            index index.html;
            add_header Cross-Origin-Embedder-Policy "require-corp" always;
            add_header Cross-Origin-Opener-Policy "same-origin" always;
        }
    }
```
### Webpack dev server
```js
const path = require('path');

module.exports = {
  //...
  devServer: {
    headers: {
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin"
    }
  },
};
```

### Vercel
```json
{
    "headers": [
        {
            "source": "/(.*)",
            "headers": [
                {
                    "key": "Cross-Origin-Embedder-Policy",
                    "value": "require-corp"
                },
                {
                    "key": "Cross-Origin-Opener-Policy",
                    "value": "same-origin"
                }
            ]
        }
    ]
}

```
