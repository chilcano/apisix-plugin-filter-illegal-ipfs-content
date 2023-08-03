-- Introduce the necessary modules/libraries we need for this plugin 
local core     = require("apisix.core")
local io       = require("io")
local ngx      = ngx
local url      = require("socket.url")
local http     = require("resty.http")
local string   = string
local pairs    = pairs
local cjson    = require("cjson")


-- Declare the plugin's name
local plugin_name = "ipfs-cache-workflow"

-- Define the plugin schema format
local plugin_schema = {
    type = "object",
    properties = {
        api_ep_1 = { 
            type = "object",
            items = {
                type = "object",
                properties = {
                    ep = { type = "string", minLength = 1},
                    method = { type = "string", default = "GET"},
                },
            },
        },
        api_ep_2 = { 
            type = "object",
            items = {
                type = "object",
                properties = {
                    ep = { type = "string", minLength = 1},
                    method = { type = "string", default = "GET"},
                },
            },
        },
        api_ep_3 = { 
            type = "object",
            items = {
                type = "object",
                properties = {
                    ep = { type = "string", minLength = 1},
                    method = { type = "string", default = "GET"},
                },
            },
        },
        api_ep_4 = { 
            type = "object",
            items = {
                type = "object",
                properties = {
                    ep = { type = "string", minLength = 1},
                    method = { type = "string", default = "GET"},
                },
            },
        },
        api_ep_error = { 
            type = "object",
            items = {
                type = "object",
                properties = {
                    ep = { type = "string", minLength = 1},
                    method = { type = "string", default = "GET"},
                },
            },
        },
    },
    required = {"api_ep_1"} -- This is a required field
}

-- Declare local function to make a request to specified url
local function make_request_to_url(url)
    local httpc = http.new()

    local res, err = httpc:request_uri(url, {
        method = ngx.req.get_method(),
        body = ngx.req.get_body_data(),
        headers = ngx.req.get_headers(),
    })

    if not res then
        ngx.log(ngx.ERR, "* Failed to make request to ", url, ": ", err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- Print the response status
    ngx.log(ngx.ERR, "* Response StatusCode: ", res.status)

    -- Parse the JSON response into a Lua table
    local data = cjson.decode(res.body)
    -- Print the entire JSON response body
    ngx.log(ngx.ERR, "* JSON Response Body: ", cjson.encode(data))

    -- Store the first response in a shared dictionary
    --ngx.ctx.step1_data = data
    --ngx.var.step1_data = data
    --ngx.req.set_header("X-step1_data", data)
    -- Store the entire response body in the shared dictionary
    local shared_dict = ngx.shared.my_shared_dict
    shared_dict:set("api1_response_body", res.body)

    return res, nil
end


-- Adv
local function make_request_to_url_adv(url, method)
    local httpc = http.new()

    local res, err = httpc:request_uri(url, {
        method = method,
        body = ngx.req.get_body_data(),
        headers = ngx.req.get_headers(),
    })

    if not res then
        ngx.log(ngx.ERR, "- Failed to make request to ", url, ": ", err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- Print the response status
    ngx.log(ngx.ERR, "- Response StatusCode: ", res.status)

    -- Parse the JSON response into a Lua table
    local data = cjson.decode(res.body)

    -- Print the entire JSON response body
    ngx.log(ngx.ERR, "- JSON Response Body: ", cjson.encode(data))

    -- Store the first response in a shared dictionary
    ngx.ctx.first_response = res

    return res, nil
end

-- Define the plugin with its version, priority, name, and schema
local _M = {
    version = 1.0,
    priority = 1000,
    name = plugin_name,
    schema = plugin_schema
}

-- Function to check if the plugin configuration is correct
function _M.check_schema(conf)
    -- Validate the configuration against the schema
    local ok, err = core.schema.check(plugin_schema, conf)
    -- If validation fails, return false and the error
    if not ok then
        return false, err
    end
    -- If validation succeeds, return true
    return true
end

-- Function to be called during the access phase
function _M.access(conf, ctx)
--function _M.rewrite(conf, ctx)
    local last_resp, err, upstream_uri_next, current_status, params_method, my_payload

    local params = {
        method = "POST",
    }

    -- Get request_uri values
    local req_uri_real = ctx.var.real_request_uri
    local splited_uri = core.utils.split_uri(req_uri_real)
    local last_uri_part_escaped = splited_uri[#splited_uri]
    local last_uri_part_unescaped = url.unescape(last_uri_part_escaped)
    local last_uri_part_b64 = ngx.encode_base64(last_uri_part_unescaped)

    -- Override the upstream uri
    upstream_uri_next = conf.api_ep_1.ep .. last_uri_part_b64

    -- Make the request to the specified URL
    local resp1, err1 = make_request_to_url(upstream_uri_next)
    if err1 then
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- Get the status
    local status1 = resp1.status
    
    if status1 == ngx.HTTP_NOT_FOUND then
        --ngx.say("We are having HTTP STATUS 404. We are going to add this IpfsResource to Cache.")
        ngx.log(ngx.ERR, "+ We are having HTTP STATUS 404. We are going to add this IpfsResource to Cache.")
        params_method = conf.api_ep_3.method
        my_payload = {
            security_provider = "phishtank",
            ipfsurl = last_uri_part_escaped
        }
        local payload_str = '{"security_provider": "phishtank", "ipfsurl": "' ..  last_uri_part_escaped .. '"}"'
        --ngx.req.set_body_data(cjson.encode(my_payload))
        ngx.req.set_body_data(payload_str)
        upstream_uri_next = conf.api_ep_3.ep 
    else 
        --ngx.say("We are having HTTP STATUS 20X. We are going to list all IpfsResources stored.")
        ngx.log(ngx.ERR, "+ We are having HTTP STATUS 20X. We are going to list all IpfsResources stored.")
        params_method = conf.api_ep_2.method
        my_payload = {
            security_provider = "%",
        }
        upstream_uri_next = conf.api_ep_2.ep .. "?" .. ngx.encode_args(my_payload)
    end

    -- Make the 2nd request to the specified URL
    local resp2, err2 = make_request_to_url_adv(upstream_uri_next, params_method)
    if err2 then
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end




    ngx.print(resp2.body)
    ngx.exit(ngx.OK)
end


-- Function to be called during the log phase
function _M.log(conf, ctx)
    -- Log the plugin configuration and the request context
    core.log.warn("conf: ", core.json.encode(conf))
    --core.log.warn("ctx: ", core.json.encode(ctx, true))
end

-- Return the plugin so it can be used by APISIX
return _M