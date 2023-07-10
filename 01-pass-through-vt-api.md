# Pass-through VT API - example

Set of scripts to implement an APISIX Plugin to filter, block and report automatically illegal content being served from IPFS.

## Tasks

1. Implement a mechanism that detects illegal content and block it automatically.
   
   1.1. Using VirusTotal - https://www.virustotal.com/
     - APISIX Custom Pipeline-Request Plugin
       * How-to: https://api7.ai/blog/chaining-api-requests-with-api-gateway
       * Plugin info: https://github.com/bzp2010/apisix-plugin-pipeline-request
    - APISIX Serverless-Pre-Function Plugin:
       * Plugin info: https://apisix.apache.org/docs/apisix/2.12/plugins/serverless/

   1.2. Using Maude (based on ClamAV) - https://github.com/allisterb/maude

3. Register what and when content has been blocked.


## I. Run local APISIX

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

- The `curl-cmds/3-create-third-route.sh` has been added to make a call to VirusTotal API.


### Step 1. Create the 3rd APISIX Route with 'pipeline-request' plugin

```json
$ sh curl-cmds/1-create-third-route.sh | jq .


```


### Step 3. Create the 2nd APISIX Route with the 'serverless' plugin

```json
$ sh curl-cmds/2-create-second-route.sh | jq .


```

### Step 4: Test the setup

```sh
$ curl -s -i http://127.0.0.1:9080/my-credit-cards


```


## III. Using Maude

TODO