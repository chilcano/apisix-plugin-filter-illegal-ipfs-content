# 01. Pass-through VirusTotal API - example

Set of scripts to create a pass-through proxy for VirusTotal API.

You need to create a VirusTotal account and get an API Key from here [https://www.virustotal.com/](https://www.virustotal.com/).

## I. Run local APISIX

### Step 1. Deploying locally APISIX and etcd on Ubuntu 22.04 or Manjaro Linux 22.1.3

```sh
$ git clone https://github.com/chilcano/apisix-plugin-filter-illegal-ipfs-content

$ cd apisix-plugin-filter-illegal-ipfs-content
```

Load the APISIX plugins we are going to use in our Routes. Update the `apisix_conf/config.yaml` file like this:
```yaml
...
plugins:
  - pipeline-request              # Used in 1st initial example
  - proxy-rewrite                 # Used in Pass-through VT API example
  - serverless-post-function      # Used in Chaining VT API example
  - file-proxy                    # Used in file-proxy example

plugin_attr:
  prometheus:
    export_addr:
      ip: "0.0.0.0"
      port: 9091
```

Once updated, run the containers.
```sh
$ docker compose up
```
Checking if all containers are up and running:
```sh
$ docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Command}}"

CONTAINER ID   IMAGE                  NAMES                      COMMAND
6fc4169504f2   apache/apisix:latest   ipfs-filter-prj-apisix-1   "/docker-entrypoint.…"
8f3d99e8094f   bitnami/etcd:3.4.15    ipfs-filter-prj-etcd-1     "/opt/bitnami/script…"
```

### Step 2. Stopping the Docker containers

```sh
$ docker compose stop

[+] Running 2/2
 ⠿ Container ipfs-filter-prj-apisix-1  Stopped                             10.9s
 ⠿ Container ipfs-filter-prj-etcd-1    Stopped                              0.4s
```

And to restart run this:
```sh
$ docker compose restart

[+] Running 2/2
 ⠿ Container ipfs-filter-prj-etcd-1    Started                             0.7s
 ⠿ Container ipfs-filter-prj-apisix-1  Started                             0.6s
```

## II. Pass-through VirusTotal API request


### Step 1. Create an APISIX Upstream for VirusTotal 

```sh
curl http://127.0.0.1:9180/apisix/admin/upstreams/4 -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" -X PUT -d '
{
   "name": "VirusTotal API upstream",
   "desc": "Add the VirusTotal API domain as the upstream",
   "type": "roundrobin",
   "scheme": "https",
   "nodes": {
      "www.virustotal.com:443": 1
   }
}'
```


### Step 2. Create the an APISIX Route with the 'proxy-rewrite' plugin

We are going to use 2 environment variables. One to provide the VirusTotal API Key and the second one is to provide the URL to check if is illegal or not.

- `VT_API_KEY`: VirusTotal API Key.
- `VT_URL_TO_CHECK`: URL to check if it is illegal or not.

You should update the `VT_API_KEY` with your own VirusTotal API Key. Set these variables:
```sh
VT_API_KEY="1234567890" 
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"
```

Once done, let's create the Route:
```sh
curl -i http://127.0.0.1:9180/apisix/admin/routes/4 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "name":"vt-proxy-pass-through",
   "desc":"Simple VT Proxy Pass Through",
   "methods":["GET"],
   "uri":"/vt-check-url/*",
   "plugins":{
      "proxy-rewrite":{
         "regex_uri":[
            "^/vt-check-url/(.*)",
            "/api/v3/urls/$1"
         ],
         "host":"www.virustotal.com",
         "headers":{
            "X-Apikey": "'${VT_API_KEY}'",
            "Content-Type": "application/json"
         }
      }
   },
   "upstream_id":4
}'
```

### Step 3: Test it

In this case, we are going to check if `VT_URL_TO_CHECK` contains an URL flagged as illegal by VirusTotal.

Now, let's make a call to already created APISIX route:

```sh
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html" 

curl http://127.0.0.1:9080/vt-check-url/$(echo -n $VT_URL_TO_CHECK | base64 -w 0 | sed 's/=//g') -s | jq .

curl http://127.0.0.1:9080/vt-check-url/$(echo -n $VT_URL_TO_CHECK | base64 -w 0 | sed 's/=//g') -s | jq '.["data"]["attributes"]["last_analysis_stats"]'

{
  "harmless": 56,
  "malicious": 19,
  "suspicious": 1,
  "undetected": 14,
  "timeout": 0
}
```

You should see a long json response which means that specified URL has been flagged as illegal.
Now, if we provide another URL which we know that is not illegal, then you should have this:

```sh
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/new-fresh-cid"
curl http://127.0.0.1:9080/vt-check-url/$(echo -n $VT_URL_TO_CHECK | base64 -w 0 | sed 's/=//g') -s | jq .

{
  "error": {
    "message": "URL \"aHR0cHM6Ly9pcGZzLmV0aC5hcmFnb24ubmV0d29yay9pcGZzL25ldy1mcmVzaC1jaWQ\" not found",
    "code": "NotFoundError"
  }
}
```

### Step 5 - Disable Route

```sh
curl http://127.0.0.1:9180/apisix/admin/routes/4  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "methods": ["GET"],
    "uri": "/ipfs/*",
    "plugins": {},
    "upstream_id": 4
}'
