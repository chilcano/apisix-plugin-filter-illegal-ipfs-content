# 03. Integrating IPFS-DB Cache to VirusTotal APISIX route



## I. Run local APISIX

```sh
$ docker compose up

$ docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Command}}"

$ docker compose stop

$ docker compose restart
```

## II. Chaining VirusTotal API request to APISIX route

### Step 1. Create 2 APISIX Upstreams


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

curl http://127.0.0.1:9180/apisix/admin/upstreams/6 -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" -X PUT -d '
{
   "name": "IPFS Logger upstream 6",
   "desc": "The localhost doesnt work, works upstream 8",
   "type": "roundrobin",
   "scheme": "http",
   "nodes": {
      "localhost:8001": 1
   }
}'

curl http://127.0.0.1:9180/apisix/admin/upstreams/7 -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" -X PUT -d '
{
   "name": "IPFS Logger upstream 7",
   "desc": "The 127.0.0.1 doesnt work, see upstream 8",
   "type": "roundrobin",
   "scheme": "http",
   "nodes": {
      "127.0.0.1:8002": 1
   }
}'


curl http://127.0.0.1:9180/apisix/admin/upstreams/8 -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" -X PUT -d '
{
   "name": "IPFS Logger upstream 8",
   "desc": "IP 192.168.1.217 - Port 8002",
   "type": "roundrobin",
   "scheme": "http",
   "nodes": {
      "192.168.1.217:8002": 1
   }
}'


# When running locally, the server should be exposed on IP or broadcast network:
❯ uvicorn app.main:app --host 192.168.1.217 --port 8002 --reload --env-file .env.ipfslogger_local

❯ uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload --env-file .env.ipfslogger_local


# Testing the upstream

curl http://127.0.0.1:9180/apisix/admin/routes/7 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri": "/api/healthcheck",
   "upstream_id": 8
}'

curl http://127.0.0.1:9080/api/healthcheck -s | jq .
{
  "message": "Hello world!. Using Python 3.11"
}

```



### Step 3. Create Routes


```sh
VT_API_KEY="your_vt_api_key"

VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"


curl http://127.0.0.1:9180/apisix/admin/routes/8 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri": "/apisix00/",
   "name": "00-list-all",
   "desc": "00 ipfslogger-list-all",
   "methods":["GET"],
   "plugins":{
      "proxy-rewrite": {
         "uri": "/api/ipfsresources/resources/",
         "headers":{
            "Content-Type":"application/json"
         }
      }
   },
   "upstream_id": 8
}'

curl http://127.0.0.1:9080/apisix00/ -s | jq .


curl http://127.0.0.1:9180/apisix/admin/routes/9 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri": "/apisix01/*",
   "name": "01-search-by-url",
   "desc": "01 ipfslogger-search-by-url",
   "methods":["GET"],
   "plugins": {
      "serverless-post-function": {
         "_meta": {
            "priority": 10000
         },
         "phase": "access",
         "functions": [
            "return function(conf, ctx)
               local core = require(\"apisix.core\")
               local url = require(\"socket.url\")
             
               local upstream_url_ini = ctx.var.upstream_uri
               local req_uri_real = ctx.var.real_request_uri
               local splited_uri = core.utils.split_uri(req_uri_real)
               local last_uri_part_escaped = splited_uri[#splited_uri]
               local last_uri_part_unescaped = url.unescape(last_uri_part_escaped)
               local last_uri_part_b64 = ngx.encode_base64(last_uri_part_unescaped)
               -- override the upstream uri
               local upstream_url_fin = upstream_url_ini .. \"/search/ipfsurl/\" .. last_uri_part_b64
               ctx.var.upstream_uri = upstream_url_fin

               ngx.log(ngx.ERR, \"(aaa) req_uri_real: \" .. req_uri_real .. \", upstream_url_ini: \" .. upstream_url_ini .. \", upstream_url_fin: \" .. upstream_url_fin .. \", last_uri_part_escaped: \" .. last_uri_part_escaped .. \", last_uri_part_unescaped: \" .. last_uri_part_unescaped)
            end"
         ]
      },
      "proxy-rewrite": {
         "host": "localhost:8002",
         "uri": "/api/ipfsresources",
         "scheme": "http"
      }
   },
   "upstream_id": 8
}'

curl http://127.0.0.1:9080/apisix01/$(source curl-cmds/url_encode.sh ${VT_URL_TO_CHECK}) -s | jq .
```


## /apisix03/* : New implementation all in Python being triggered by single APISIX route

```sh

curl http://127.0.0.1:9180/apisix/admin/routes/10 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri": "/apisix03/*",
   "name": "03 ipfs url cache",
   "desc": "Trigger ipfs-url-cache and return verdict from 1 URLValidator",
   "methods":["GET"],
   "plugins": {
      "serverless-post-function": {
         "_meta": {
            "priority": 10000
         },
         "phase": "access",
         "functions": [
            "return function(conf, ctx)
               local core = require(\"apisix.core\")
               local url = require(\"socket.url\")
             
               local upstream_url_ini = ctx.var.upstream_uri
               local req_uri_real = ctx.var.real_request_uri
               local splited_uri = core.utils.split_uri(req_uri_real)
               local last_uri_part_escaped = splited_uri[#splited_uri]
               local last_uri_part_unescaped = url.unescape(last_uri_part_escaped)
               local last_uri_part_b64 = ngx.encode_base64(last_uri_part_unescaped)
               local last_uri_part_b64_escaped = url.escape(last_uri_part_b64)

               -- override the upstream uri
               --local upstream_url_fin = upstream_url_ini .. \"/search/ipfsurl/\" .. last_uri_part_b64
               --local upstream_url_fin = upstream_url_ini .. \"/cache/ipfsurl/\" .. last_uri_part_b64
               local upstream_url_fin = upstream_url_ini .. \"/cache/ipfsurl/\" .. last_uri_part_b64_escaped
               ctx.var.upstream_uri = upstream_url_fin

               ngx.log(ngx.ERR, \"req_uri_real: \" .. req_uri_real)
               ngx.log(ngx.ERR, \"upstream_url_ini: \" .. upstream_url_ini)
               ngx.log(ngx.ERR, \"upstream_url_fin: \" .. upstream_url_fin)
               ngx.log(ngx.ERR, \"last_uri_part_escaped: \" .. last_uri_part_escaped)
               ngx.log(ngx.ERR, \"last_uri_part_unescaped: \" .. last_uri_part_unescaped)
               ngx.log(ngx.ERR, \"last_uri_part_b64: \" .. last_uri_part_b64)
               ngx.log(ngx.ERR, \"last_uri_part_b64_escaped: \" .. last_uri_part_b64_escaped)
            end"
         ]
      },
      "proxy-rewrite": {
         "host": "localhost:8002",
         "uri": "/api/ipfsresources",
         "scheme": "http"
      }
   },
   "upstream_id": 8
}'


VT_API_KEY="your_vt_api_key"
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeig2vab5dyxfslradqqcrears2joaijxljtgtdkiykpn7l6uzwkh24/nniOwadd2.html"

curl http://127.0.0.1:9080/apisix03/$(source curl-cmds/url_encode.sh ${VT_URL_TO_CHECK}) -s | jq .


```



## /apisix04/* :  New implementation all in Python being triggered by single APISIX route

```sh

curl http://127.0.0.1:9180/apisix/admin/routes/11 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri": "/apisix04/*",
   "name": "04 ipfs url cache",
   "desc": "Trigger ipfs-url-cache and return verdict from multiples URLValidators",
   "methods":["GET"],
   "plugins": {
      "serverless-post-function": {
         "_meta": {
            "priority": 10000
         },
         "phase": "access",
         "functions": [
            "return function(conf, ctx)
               local core = require(\"apisix.core\")
               local url = require(\"socket.url\")
             
               local upstream_url_ini = ctx.var.upstream_uri
               local req_uri_real = ctx.var.real_request_uri
               local splited_uri = core.utils.split_uri(req_uri_real)
               local last_uri_part_escaped = splited_uri[#splited_uri]
               local last_uri_part_unescaped = url.unescape(last_uri_part_escaped)
               local last_uri_part_b64 = ngx.encode_base64(last_uri_part_unescaped)
               local last_uri_part_b64_escaped = url.escape(last_uri_part_b64)

               local upstream_url_fin = upstream_url_ini .. \"/cache/ipfsurlfull/\" .. last_uri_part_b64_escaped
               ctx.var.upstream_uri = upstream_url_fin

               ngx.log(ngx.ERR, \"req_uri_real: \" .. req_uri_real)
               ngx.log(ngx.ERR, \"upstream_url_ini: \" .. upstream_url_ini)
               ngx.log(ngx.ERR, \"upstream_url_fin: \" .. upstream_url_fin)
               ngx.log(ngx.ERR, \"last_uri_part_escaped: \" .. last_uri_part_escaped)
               ngx.log(ngx.ERR, \"last_uri_part_unescaped: \" .. last_uri_part_unescaped)
               ngx.log(ngx.ERR, \"last_uri_part_b64: \" .. last_uri_part_b64)
               ngx.log(ngx.ERR, \"last_uri_part_b64_escaped: \" .. last_uri_part_b64_escaped)
            end"
         ]
      },
      "proxy-rewrite": {
         "host": "localhost:8002",
         "uri": "/api/ipfsresources",
         "scheme": "http"
      }
   },
   "upstream_id": 8
}'


VT_API_KEY="your_vt_api_key"
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeig2vab5dyxfslradqqcrears2joaijxljtgtdkiykpn7l6uzwkh24/nniOwadd2.html"
VT_URL_TO_CHECK="holamundo"

curl http://127.0.0.1:9080/apisix04/$(source curl-cmds/url_encode.sh ${VT_URL_TO_CHECK}) -s | jq .


```





## Custom APISIX Plugins

```sh
# Plugins hotreload
curl http://127.0.0.1:9180/apisix/admin/plugins/reload -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT




curl http://127.0.0.1:9180/apisix/admin/routes/201 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri":"/route/to/apiplugin1/*",
   "methods": ["GET"],
   "plugins": {
      "api1-plugin": {
        "_meta": {"disable": false, "priority": 50000},
         "ep": {
            "url": "https://random-data-api.com/api/v2/beers",
            "ssl_verify": false,
            "timeout": 2500
         }
      }
   }
}'

# curl http://127.0.0.1:9080/route/to/apiplugin1/hello1 -s -X GET | jq .

curl http://127.0.0.1:9180/apisix/admin/routes/202 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri":"/route/to/apiplugin2/*",
   "methods": ["GET"],
   "plugins": {
      "api2-plugin": {
        "_meta": {"disable": false, "priority": 50000},
         "ep": {
            "url": "https://random-data-api.com/api/v2/banks",
            "ssl_verify": false,
            "timeout": 2500
         }
      }
   }
}'

# curl http://127.0.0.1:9080/route/to/apiplugin2/hello2 -s -X GET | jq .



curl http://127.0.0.1:9180/apisix/admin/routes/30 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "uri": "/mypipeline",
   "plugins": {
      "pipeline-request": {
         "nodes": [
            {
               "url": "http://127.0.0.1:9080/route/to/apiplugin1/*"
            },
            {
               "url": "http://127.0.0.1:9080/route/to/apiplugin2/*"
            }
         ]
      }
   }
}'


# Plugins hot-reload
curl http://127.0.0.1:9180/apisix/admin/plugins/reload -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT

# Example
curl http://127.0.0.1:9080/mypipeline -s | jq .

```








## All in Python




















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

