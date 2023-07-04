# VT API call example

VT_API_KEY="4187ec98ceb9ee92849c10be18cb4b474b33575784799ccfe280f77d1a849e42"
VT_URL_TO_CHECK="https://ipfs.eth.aragon.network/ipfs/bafybeiffwwcyirxa2hmzq3mxsihjxltlaabxmpo2tjkoboaykemvh63qg4/alltheglory20_officeui.html"
VT_URL_TO_CHECK_B64_WO_PAD=$(echo -n $VT_URL_TO_CHECK | base64 -w 0 | sed 's/=//g')

curl --request GET --url https://www.virustotal.com/api/v3/urls/$VT_URL_TO_CHECK_B64_WO_PAD -H "x-apikey: ${VT_API_KEY}" -s | jq .


# Step 1 - Create an upstream for the VT API

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

# Step 2 - Create a plugin-config for the VT API info-url endpoint

curl http://127.0.0.1:9180/apisix/admin/plugin_configs/4 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "plugins":{
      "proxy-rewrite":{
         "regex_uri":[
            "^/ipfs/(.*)",
            "/api/v3/urls/$1"
         ],
         "host":"www.virustotal.com",
         "headers":{
            "X-Apikey":"4187ec98ceb9ee92849c10be18cb4b474b33575784799ccfe280f77d1a849e42",
            "Content-Type":"application/json"
         }
      }
   }
}'

# ==>> plugin_configs didn't work *********************


# Step 3 - Set up a Route for the VT info-url API 

curl -i http://127.0.0.1:9180/apisix/admin/routes/4 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "name":"VirusTotal API info-url endpoint route",
   "desc":"Create a new route in APISIX for the VirusTotal API info-url endpoint",
   "methods":["GET"],
   "uri":"/ipfs/*",
   "plugin_config":4,
   "upstream_id":4
}'

# ==>> route didn't work because plugin_configs/4 has issues *********************



curl -i http://127.0.0.1:9180/apisix/admin/routes/4 -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
   "name":"VirusTotal API info-url endpoint route",
   "desc":"Create a new route in APISIX for the VirusTotal API info-url endpoint",
   "methods":["GET"],
   "uri":"/ipfs/*",
   "plugins":{
      "proxy-rewrite":{
         "regex_uri":[
            "^/ipfs/(.*)",
            "/api/v3/urls/$1"
         ],
         "host":"www.virustotal.com",
         "headers":{
            "X-Apikey":"4187ec98ceb9ee92849c10be18cb4b474b33575784799ccfe280f77d1a849e42",
            "Content-Type":"application/json"
         }
      }
   },
   "upstream_id":4
}'

# Step 4 - Disable Route

curl http://127.0.0.1:9180/apisix/admin/routes/4  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' -X PUT -d '
{
    "methods": ["GET"],
    "uri": "/ipfs/*",
    "plugins": {},
    "upstream_id": 4
}'


# Step 5 - Test VT API

curl http://127.0.0.1:9080/ipfs/$VT_URL_TO_CHECK_B64_WO_PAD -s | jq .

