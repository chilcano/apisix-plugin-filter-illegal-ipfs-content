# Create a Route 1 (/my-credit-cards plugin) with pipeline-request enabled.

curl -s -X PUT 'http://127.0.0.1:9180/apisix/admin/routes/1' \
--header 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
--header 'Content-Type: application/json' \
--data-raw '{
   "uri":"/my-credit-cards",
   "plugins":{
      "pipeline-request":{
         "nodes":[
            {
              "url":"https://random-data-api.com/api/v2/credit_cards"
            },
            {
              "url":"http://127.0.0.1:9080/filter"
            }
         ]
      }
   }
}'