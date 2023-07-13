"serverless-pre-function": {
    "disable": false,
    "functions": [
      "return function(conf, ctx) 
        local core = require(\"apisix.core\")  
        local httpc = require(\"resty.http\").new() 

        ngx.req.read_body() 

        local res, err = httpc:request_uri(\"http://host.docker.internal:9191/transform\", 
                                            {
                                                method = \"POST\", 
                                                body = ngx.req.get_body_data(), 
                                                headers = { 
                                                    [\"Content-Type\"] = \"application/json\", 
                                                    [\"Upstream\"] = core.request.header(ctx, \"Upstream\"), 
                                                    [\"Transformer\"] = core.request.header(ctx, \"Transformer\")
                                                }
                                            }
                                        ) 
        ngx.req.set_body_data(res.body)
        
        ngx.req.init_body() 
        ngx.req.append_body(res.body) 
        ngx.req.finish_body()
    end"
    ],
    "phase": "before_proxy"
}