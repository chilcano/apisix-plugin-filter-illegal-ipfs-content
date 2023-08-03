# 02. Chaining VirusTotal API request to existing APISIX route - example

Set of scripts to implement an APISIX Plugin to filter, block and report automatically illegal content being served from IPFS.

You need to create a VirusTotal account and get an API Key from here [https://www.virustotal.com/](https://www.virustotal.com/).

This article automates the manual process followed in [01-pass-through-vt-api.md](01-pass-through-vt-api.md) and this case we using 2 APISIX plugins, they are `serverless-post-function` and `proxy-rewrite`.


Process followed:

1. APISIX receive a request `http://local-apisix/api02/abcd1234`.
2. The `serverless-post-function` plugin is triggered and goes through these steps:
  * It gets `abcd1234`, encode to base64 and remove padding.
  * It overrides the `ctx.var.upstream_uri` with existing value concatenated with previous base64 without padding value.
  * Once completed, the next plugin is triggered.
3. The `proxy-rewrite` is executed and and goes through these steps:
  * The incoming request is overwritten as the URI as the HTTP Headers.


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

## II. Chaining VirusTotal API request to APISIX route

### Step 1. Create 2 APISIX Upstreams

We are going to create 2 APISIX upstreams, one for VirusTotal API and a second one for testing purposes to `echo-api.3scale.net`.
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


curl http://127.0.0.1:9180/apisix/admin/upstreams/5 -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" -X PUT -d '
{
   "name": "Echo API upstream",
   "desc": "Echo API as the upstream",
   "type": "roundrobin",
   "scheme": "https",
   "nodes": {
      "echo-api.3scale.net": 1
   }
}'
```


### Step 2. Create the a Route with the 'proxy-rewrite' plugin and using Echo upstream

We are going to use 2 environment variables. One to provide the VirusTotal API Key and the second one is to provide the URL to check if is illegal or not.

- `VT_API_KEY`: VirusTotal API Key.
- `VT_URL_TO_CHECK`: URL to check if it is illegal or not.

You should update the `VT_API_KEY` with your own VirusTotal API Key. Set these variables:
```sh
VT_API_KEY="1234567890" 
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"
```

Once done, let's create the Route, but in this case we a re going to use the Echo Upstream only for testing. Once tested, we will sitch to VirusTotal upstream changing `upstream_id` from `5` to `4`.

```sh
curl -i http://127.0.0.1:9180/apisix/admin/routes/5 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "name":"mock-vt-url-check",
   "desc":"Mocks checking URL against VT",
   "methods":["GET"],
   "uri":"/api01/*",
   "plugins":{
      "serverless-post-function": {
         "phase": "access",
         "functions": [
            "return function(conf, ctx)
               local core = require(\"apisix.core\")
               local url = require(\"socket.url\")
             
               local upstream_url_ini = ctx.var.upstream_uri
               local req_uri_real = ctx.var.real_request_uri
               local splited_uri = core.utils.split_uri(req_uri_real)
               local last_uri_part = splited_uri[#splited_uri]
               local last_uri_part_decoded = url.unescape(last_uri_part)
               local last_uri_part_b64 = ngx.encode_base64(last_uri_part_decoded)
               local chars_to_remove = \"[=]\"
               local upstream_url_fin = upstream_url_ini .. \"/\" .. last_uri_part_b64
               ctx.var.upstream_uri = string.gsub(upstream_url_fin, chars_to_remove, \"\")

               ngx.log(ngx.ERR, \"req_uri_real: \" .. req_uri_real .. \", upstream_url_ini: \" .. upstream_url_ini .. \", upstream_url_fin: \" .. upstream_url_fin .. \", last_uri_part: \" .. last_uri_part .. \", last_uri_part_decoded: \" .. last_uri_part_decoded)
            end"
         ]
      },
      "proxy-rewrite":{
         "uri": "/api/v3/urls",
         "host":"echo-api.3scale.net",
         "headers":{
            "X-Apikey":"'${VT_API_KEY}'",
            "Content-Type":"application/json"
         }
      }
   },
   "upstream_id": 5
}'

```

Let's to test it.

```sh
curl http://127.0.0.1:9080/api01/abcd1234 -s | jq .
```

```json
{
  "method": "GET",
  "path": "/api/v3/urls/YWJjZDEyMzQ",
  "args": "",
  "body": "",
  "headers": {
    "HTTP_VERSION": "HTTP/1.1",
    "HTTP_HOST": "echo-api.3scale.net",
    "HTTP_X_REAL_IP": "172.18.0.1",
    "HTTP_X_FORWARDED_FOR": "172.18.0.1,2.120.146.198",
    "HTTP_X_FORWARDED_PROTO": "https",
    "HTTP_X_FORWARDED_HOST": "127.0.0.1",
    "HTTP_X_FORWARDED_PORT": "9080",
    "HTTP_USER_AGENT": "curl/8.1.2",
    "HTTP_ACCEPT": "*/*",
    "HTTP_X_APIKEY": "1234567890",
    "CONTENT_TYPE": "application/json",
    "HTTP_X_ENVOY_EXTERNAL_ADDRESS": "2.120.146.198",
    "HTTP_X_REQUEST_ID": "335ab6af-3a31-49fb-b1c8-bc62f909dc15",
    "HTTP_X_ENVOY_EXPECTED_RQ_TIMEOUT_MS": "15000"
  },
  "uuid": "0018a552-bdcd-4648-aa7c-e69257fdfb2b"
}
```

You should have this `"path": "/api/v3/urls/YWJjZDEyMzQ"` which means that APISIX route has been executed succesfully.
If we get the base64 without padding of `abcd1234`, that should match with above value.
```sh
echo -n 'abcd1234' | base64 -w 0 | sed 's/=//g'

YWJjZDEyMzQ
```

What if check a complex URL?
```sh
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/abcd1234"

curl http://127.0.0.1:9080/api01/$VT_URL_TO_CHECK -s | jq .
```

You will see that complex string doesn't work because it requires be hex encoded before.
The APISIX route only processes always the last part of a URL, in this case `abcd1234`, but I want to process the entire URL `https://ipfs.eth.aragon.network/ipfs/abcd1234`.
```json
{
  "method": "GET",
  "path": "/api/v3/urls/YWJjZDEyMzQ",
  "args": "",
  "body": "",
  "headers": {
    "HTTP_VERSION": "HTTP/1.1",
    "HTTP_HOST": "echo-api.3scale.net",
    "HTTP_X_REAL_IP": "172.18.0.1",
    "HTTP_X_FORWARDED_FOR": "172.18.0.1,2.120.146.198",
    "HTTP_X_FORWARDED_PROTO": "https",
    "HTTP_X_FORWARDED_HOST": "127.0.0.1",
    "HTTP_X_FORWARDED_PORT": "9080",
    "HTTP_USER_AGENT": "curl/8.1.2",
    "HTTP_ACCEPT": "*/*",
    "HTTP_X_APIKEY": "1234567890",
    "CONTENT_TYPE": "application/json",
    "HTTP_X_ENVOY_EXTERNAL_ADDRESS": "2.120.146.198",
    "HTTP_X_REQUEST_ID": "43b0cda3-6ea6-46f4-be88-72db20989054",
    "HTTP_X_ENVOY_EXPECTED_RQ_TIMEOUT_MS": "15000"
  },
  "uuid": "18d0a688-1f62-4af8-93dd-7d330cd0d582"
}
```


Not problem, I have a bash script (`curl-cmds/url_encode.sh`) to encode URLs, only I should hex encode the URL before sending it to APISIX:
```sh
VT_URL_TO_CHECK_ENCODED=$(source curl-cmds/url_encode.sh ${VT_URL_TO_CHECK})
```

Now, let's try it again:
```sh
curl http://127.0.0.1:9080/api01/$VT_URL_TO_CHECK_ENCODED -s | jq .
```
And we will get this:
```json
{
  "method": "GET",
  "path": "/api/v3/urls/aHR0cHM6Ly9pcGZzLmV0aC5hcmFnb24ubmV0d29yay9pcGZzL2FiY2QxMjM0",
  "args": "",
  "body": "",
  "headers": {
    "HTTP_VERSION": "HTTP/1.1",
    "HTTP_HOST": "echo-api.3scale.net",
    "HTTP_X_REAL_IP": "172.18.0.1",
    "HTTP_X_FORWARDED_FOR": "172.18.0.1,2.120.146.198",
    "HTTP_X_FORWARDED_PROTO": "https",
    "HTTP_X_FORWARDED_HOST": "127.0.0.1",
    "HTTP_X_FORWARDED_PORT": "9080",
    "HTTP_USER_AGENT": "curl/8.1.2",
    "HTTP_ACCEPT": "*/*",
    "HTTP_X_APIKEY": "1234567890",
    "CONTENT_TYPE": "application/json",
    "HTTP_X_ENVOY_EXTERNAL_ADDRESS": "2.120.146.198",
    "HTTP_X_REQUEST_ID": "e08398a7-275a-416c-b520-942a277f13e3",
    "HTTP_X_ENVOY_EXPECTED_RQ_TIMEOUT_MS": "15000"
  },
  "uuid": "1058e249-a01d-4083-8279-9c50fd9c8b28"
}
```

Where the URL being used here `"path": "/api/v3/urls/aHR0cHM6Ly9pcGZzLmV0aC5hcmFnb24ubmV0d29yay9pcGZzL2FiY2QxMjM0` corresponds to `https://ipfs.eth.aragon.network/ipfs/abcd1234`:

```sh
echo -n $VT_URL_TO_CHECK | base64 -w 0 | sed 's/=//g'

aHR0cHM6Ly9pcGZzLmV0aC5hcmFnb24ubmV0d29yay9pcGZzL2FiY2QxMjM0
```


### Step 3. Create the a Route with the 'proxy-rewrite' plugin and using VirusTotal upstream

Only we should change the `upstream_id` from `5` to `4` in the previous APISIX route or if you prefer, create a new route with different `uri` to avoid conflicts.

Remember, you should update the VirusTotal API key with your own.
```sh
VT_API_KEY="4187ec98ceb9ee92849c10be18cb4b474b33575784799ccfe280f77d1a849e42"
```

Once updated, update the previous APISIX route.
```sh
curl -i http://127.0.0.1:9180/apisix/admin/routes/6 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "name":"vt-url-check",
   "desc":"Checks URL against VT",
   "methods":["GET"],
   "uri":"/api02/*",
   "plugins":{
      "serverless-post-function": {
         "phase": "access",
         "functions": [
            "return function(conf, ctx)
               local core = require(\"apisix.core\")
               local url = require(\"socket.url\")
             
               local upstream_url_ini = ctx.var.upstream_uri
               local req_uri_real = ctx.var.real_request_uri
               local splited_uri = core.utils.split_uri(req_uri_real)
               local last_uri_part = splited_uri[#splited_uri]
               local last_uri_part_decoded = url.unescape(last_uri_part)
               local last_uri_part_b64 = ngx.encode_base64(last_uri_part_decoded)
               local chars_to_remove = \"[=]\"
               local upstream_url_fin = upstream_url_ini .. \"/\" .. last_uri_part_b64
               ctx.var.upstream_uri = string.gsub(upstream_url_fin, chars_to_remove, \"\")

               ngx.log(ngx.ERR, \"req_uri_real: \" .. req_uri_real .. \", upstream_url_ini: \" .. upstream_url_ini .. \", upstream_url_fin: \" .. upstream_url_fin .. \", last_uri_part: \" .. last_uri_part .. \", last_uri_part_decoded: \" .. last_uri_part_decoded)
            end"
         ]
      },
      "proxy-rewrite":{
         "uri": "/api/v3/urls",
         "host":"www.virustotal.com",
         "headers":{
            "X-Apikey":"'${VT_API_KEY}'",
            "Content-Type":"application/json"
         }
      }
   },
   "upstream_id": 4
}'

```

Let's to test it. Only for convenience, we are going to pass the URL to check as an environment variable.

```sh
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/abcd1234"

curl http://127.0.0.1:9080/api02/$(source curl-cmds/url_encode.sh ${VT_URL_TO_CHECK}) -s | jq .

{
  "error": {
    "message": "URL \"aHR0cHM6Ly9pcGZzLmV0aC5hcmFnb24ubmV0d29yay9pcGZzL2FiY2QxMjM0\" not found",
    "code": "NotFoundError"
  }
}
```

And using an URL flagged as illegal.
```sh
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"

curl http://127.0.0.1:9080/api02/$(source curl-cmds/url_encode.sh ${VT_URL_TO_CHECK}) -s | jq .
```

If everything goes well, you should see this:

```json
{
  "data": {
    "attributes": {
      "last_http_response_content_sha256": "a549f62ba6157bf6ab24be899686605fa5089b191517af4affb68ee2bcbcbd2d",
      "last_http_response_code": 403,
      "last_final_url": "https://aragon-gateway.infura-ipfs.io/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html",
      "last_http_response_content_length": 33,
      "url": "https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html",
      "redirection_chain": [
        "https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"
      ],
      "last_analysis_date": 1687106093,
      "tags": [],
      "last_analysis_results": {
        "Bkav": {
          "category": "undetected",
          "result": "unrated",
          "method": "blacklist",
          "engine_name": "Bkav"
        },
        "CMC Threat Intelligence": {
          "category": "harmless",
          "result": "clean",
          "method": "blacklist",
          "engine_name": "CMC Threat Intelligence"
        },
...
```

Testing other URLs and parsing the response:
```sh
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeihaghuxkwboq7367jupfatm2mt5kmviygerp6pfux7ykkstb5vng4/dakwerken.html"

curl http://127.0.0.1:9080/api02/$(source curl-cmds/url_encode.sh ${VT_URL_TO_CHECK}) -s | jq '.["data"]["attributes"]["last_analysis_stats"]'

{
  "harmless": 57,
  "malicious": 17,
  "suspicious": 0,
  "undetected": 16,
  "timeout": 0
}
```


### Step 4 - Disable the Routes

```sh
curl http://127.0.0.1:9180/apisix/admin/routes/5  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "methods": ["GET"],
    "uri": "/api01/*",
    "plugins": {},
    "upstream_id": 5
}'

curl http://127.0.0.1:9180/apisix/admin/routes/6  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "methods": ["GET"],
    "uri": "/api01/*",
    "plugins": {},
    "upstream_id": 4
}'
```


## Resources

1. Using VirusTotal - https://www.virustotal.com/
   - APISIX Custom Pipeline-Request Plugin
      * How-to: https://api7.ai/blog/chaining-api-requests-with-api-gateway
      * Plugin info: https://github.com/bzp2010/apisix-plugin-pipeline-request
   - APISIX Serverless-Pre-Function Plugin:
      * Plugin info: https://apisix.apache.org/docs/apisix/2.12/plugins/serverless/
2. Using Maude (based on ClamAV) - https://github.com/allisterb/maude
3. Other security services to check illegal content:
   - https://urlscan.io/result/26647355-3e41-4d57-8af0-616e09d14c76/
   - https://badbits.dwebops.pub/
4. Lua, OpenResty and Ballerina documentation:
   - https://openresty.org/en/getting-started.html
   - https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/
   - https://ballerina.io/learn/manage-data-persistence-with-bal-persist/
   - https://apisix.apache.org/docs/general/code-samples/