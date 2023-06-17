# APISIX Plugin to filter illegal IPFS content

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

