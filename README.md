# Chaining API requests - example

This repo is based on:

- APISIX Custom Pipeline-Request Plugin
  * How-to: https://api7.ai/blog/chaining-api-requests-with-api-gateway
  * Plugin info: https://github.com/bzp2010/apisix-plugin-pipeline-request
- APISIX Serverless-Pre-Function Plugin:
  * Plugin info: https://apisix.apache.org/docs/apisix/2.12/plugins/serverless/


## I. Running the existing chaining API requests example 

- The `user: root` line has been added to  `docker-compose.yml` file to run it on Ubuntu 22.04. Without that, you will have write permission errors in `apisix/logs` folder.
- The `name: ipfs-filter-prj` line has been added to  `docker-compose.yml` file to set up a friendly name to running containers.
- The `curl-cmds/1-create-first-route.sh` has been added.


### Step 1. Deploying locally APISIX and etcd on Ubuntu 22.04 or Manjaro Linux 22.1.3

```sh
$ git clone https://github.com/chilcano/apisix-plugin-filter-illegal-ipfs-content

$ cd apisix-plugin-filter-illegal-ipfs-content

$ docker compose up
```
Checking if all containers are up and running:
```sh
$ docker ps --format "table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Command}}"

CONTAINER ID   IMAGE                  NAMES                      COMMAND
6fc4169504f2   apache/apisix:latest   ipfs-filter-prj-apisix-1   "/docker-entrypoint.…"
8f3d99e8094f   bitnami/etcd:3.4.15    ipfs-filter-prj-etcd-1     "/opt/bitnami/script…"
```

### Step 2. Create the 1st APISIX Route with 'pipeline-request' plugin

```json
$ sh curl-cmds/1-create-first-route.sh | jq .

{
  "key": "/apisix/routes/1",
  "value": {
    "id": "1",
    "plugins": {
      "pipeline-request": {
        "nodes": [
          {
            "url": "https://random-data-api.com/api/v2/credit_cards",
            "keepalive_timeout": 60000,
            "ssl_verify": false,
            "timeout": 3000,
            "keepalive": true,
            "keepalive_pool": 5
          },
          {
            "url": "http://127.0.0.1:9080/filter",
            "keepalive_timeout": 60000,
            "ssl_verify": false,
            "timeout": 3000,
            "keepalive": true,
            "keepalive_pool": 5
          }
        ]
      }
    },
    "update_time": 1687017979,
    "status": 1,
    "create_time": 1687017979,
    "priority": 0,
    "uri": "/my-credit-cards"
  }
}
```


### Step 3. Create the 2nd APISIX Route with the 'serverless' plugin

```json
$ sh curl-cmds/2-create-second-route.sh | jq .

{
  "key": "/apisix/routes/2",
  "value": {
    "id": "2",
    "plugins": {
      "serverless-pre-function": {
        "phase": "access",
        "functions": [
          "return function(conf, ctx) \n            local core = require(\"apisix.core\")\n            local cjson = require(\"cjson.safe\")\n\n            -- Get the request body\n            local body = core.request.get_body()\n            -- Decode the JSON body\n            local decoded_body = cjson.decode(body)\n\n            -- Hide the credit card number\n            decoded_body.credit_card_number = \"****-****-****-****\"\n            core.response.exit(200, decoded_body); \n        end"
        ]
      }
    },
    "update_time": 1687018066,
    "status": 1,
    "create_time": 1687018066,
    "priority": 0,
    "uri": "/filter"
  }
}
```

### Step 4. Test the setup

```sh
$ curl -s -i http://127.0.0.1:9080/my-credit-cards

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Server: APISIX/3.2.1
Date: Sat, 17 Jun 2023 16:09:58 GMT

{"id":6304,"credit_card_type":"dankort","credit_card_number":"****-****-****-****","uid":"ae7ed660-26a2-496d-9556-33609c03aecf","credit_card_expiry_date":"2026-06-16"}
```


Or prettifing the output:
```json
$ curl -s http://127.0.0.1:9080/my-credit-cards | jq .

{
  "id": 9824,
  "credit_card_expiry_date": "2025-06-16",
  "uid": "3e972a3a-131a-46e3-8dea-9a0bf8ec72aa",
  "credit_card_type": "american_express",
  "credit_card_number": "****-****-****-****"
}
```

### Step 5. Stopping the Docker containers

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
