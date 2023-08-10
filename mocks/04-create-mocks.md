# Mocking APIs


## 1. Enable Mocking Plugin in APISIX

```sh
$ nano apisix_conf/config.yaml

...
plugins:
  - serverless-pre-function       
  - pipeline-request              
  - proxy-rewrite                 
  - serverless-post-function      
  - file-proxy                    
  - server-info
  - mocking                       # Used to create mocks

```
Reload the APISIX Plugins:
```sh
$ curl http://127.0.0.1:9180/apisix/admin/plugins/reload -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT
```


## 2. Create routes 



### Example 01. Creating a route definition in json with mocking plugin and response_schema in json format


__1. Create `route_mock_simple.json` file__

```sh
$ cat route_mock_simple.json
```


__2. Apply the route__

```sh
curl http://127.0.0.1:9180/apisix/admin/routes/101 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d @route_mock_simple.json

```

__3. Test the route__

```sh
curl http://127.0.0.1:9080/mock/simple -i

curl http://127.0.0.1:9080/mock/simple -s | jq .
```


### Example 02. Creating a route definition mocking VirusTotal HTTP_STATUS 200 and illegal URL


__1. Create `route_mock_vt_url01_illegal_200.json` file__


This route has this `response_example` as string. That means we should escape before.
```json
{
  "message": "This is a mock response",
  "details": "Some additional details",
  "data": {
    "attributes": {
      "url": "https://ipfs.eth.aragon.network/ipfs/bafybeihaghuxkwboq7367jupfatm2mt5kmviygerp6pfux7ykkstb5vng4/dakwerken.html",
      "last_analysis_stats": {
        "harmless": 57,
        "malicious": 17,
        "suspicious": 0,
        "undetected": 16,
        "timeout": 0
      }
    },
    "type": "url",
    "id": "ff5e5ab50a97063b3913f815d1dbfa713ffa5a5732500429e1159c915b51ad57",
    "links": {
      "self": "https://www.virustotal.com/api/v3/urls/ff5e5ab50a97063b3913f815d1dbfa713ffa5a5732500429e1159c915b51ad57"
    }
  }
}
```
and using this [https://codebeautify.org/json-escape-unescape](https://codebeautify.org/json-escape-unescape), we got an escaped string which we can remove the `\n` and `\s` (blank spaces) and finally have this:
```json
{\"message\":\"Thisisamockresponse\",\"details\":\"Someadditionaldetails\",\"data\":{\"attributes\":{\"url\":\"https://ipfs.eth.aragon.network/ipfs/bafybeihaghuxkwboq7367jupfatm2mt5kmviygerp6pfux7ykkstb5vng4/dakwerken.html\",\"last_analysis_stats\":{\"harmless\":57,\"malicious\":17,\"suspicious\":0,\"undetected\":16,\"timeout\":0}},\"type\":\"url\",\"id\":\"ff5e5ab50a97063b3913f815d1dbfa713ffa5a5732500429e1159c915b51ad57\",\"links\":{\"self\":\"https://www.virustotal.com/api/v3/urls/ff5e5ab50a97063b3913f815d1dbfa713ffa5a5732500429e1159c915b51ad57\"}}}
```


Once completed, let's create the route.
```json
$ cat route_mock_vt_url01_illegal_200.json
```


__2. Apply the route__

```sh
curl http://127.0.0.1:9180/apisix/admin/routes/102 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d @route_mock_vt_url01_illegal_200.json
```

__3. Test the route__

```sh
curl http://127.0.0.1:9080/mock/vt/url01_illegal_200 -i

curl http://127.0.0.1:9080/mock/vt/url01_illegal_200 -s | jq .

curl http://127.0.0.1:9080/mock/vt/url01_illegal_200 -s | jq '.["data"]["attributes"]["last_analysis_stats"]'
```


### Example 03. Creating a route definition mocking VirusTotal HTTP_STATUS 200 and legal URL


__1. Create `route_mock_vt_url02_legal_200.json` file__


This route has this `response_example` as string. That means we should escape before.
```json
{
  "data": {
    "attributes": {
      "url": "https://ipfs.eth.aragon.network/ipfs/QmNxCK5A9yGWP7skEU1h62qgXQNDMBMRv3Kz6RQxXNn6Y4",
      "last_analysis_stats": {
        "harmless": 65,
        "malicious": 7,
        "suspicious": 1,
        "undetected": 17,
        "timeout": 0
      }
    },
    "type": "url"
  }
}
```

__2. Apply the route__

```sh
curl http://127.0.0.1:9180/apisix/admin/routes/103 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d @route_mock_vt_url02_legal_200.json
```

__3. Test the route__

```sh
curl http://127.0.0.1:9080/mock/vt/url02_legal_200 -s | jq '.["data"]["attributes"]["last_analysis_stats"]'
```