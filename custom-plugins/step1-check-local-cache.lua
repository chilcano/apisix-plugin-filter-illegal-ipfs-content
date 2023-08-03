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
local plugin_name = "step1-check-local-cache"

-- Define the plugin schema format
local plugin_schema = {
    type = "object",
    properties = {
        api_ep = {
            type = "string" -- The api_ep of the file to be served
        },
    },
    required = {"api_ep"} -- The api_ep is a required field
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
        ngx.log(ngx.ERR, "1st Failed to make request to ", url, ": ", err)
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- Print the response status
    ngx.log(ngx.ERR, "1st Response StatusCode: ", res.status)

    -- Parse the JSON response into a Lua table
    local data = cjson.decode(res.body)

    -- Access specific value from the JSON data (for example, "key1" from the JSON response)
    --local value = data["key1"]
    --ngx.log(ngx.ERR, "Value of key1 in JSON response: ", value)

    -- Print the entire JSON response body
    ngx.log(ngx.ERR, "1st JSON Response Body: ", cjson.encode(data))

    -- Store the first response in a shared dictionary
    --ngx.ctx.step1_data = data
    --ngx.var.step1_data = data
    --ngx.req.set_header("X-step1_data", data)
    -- Store the entire response body in the shared dictionary
    local shared_dict = ngx.shared.my_shared_dict
    shared_dict:set("api1_response_body", res.body)

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
--function _M.access(conf, ctx)
function _M.rewrite(conf, ctx)
    -- Get request_uri values
    local req_uri_real = ctx.var.real_request_uri
    local splited_uri = core.utils.split_uri(req_uri_real)
    local last_uri_part_escaped = splited_uri[#splited_uri]
    local last_uri_part_unescaped = url.unescape(last_uri_part_escaped)
    local last_uri_part_b64 = ngx.encode_base64(last_uri_part_unescaped)

    -- Override the upstream uri
    local upstream_url_fin = conf.api_ep .. last_uri_part_b64

    -- Make the request to the specified URL
    local response, err = make_request_to_url(upstream_url_fin)
    if err then
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- Forward the response status, headers, and body back to the client
    ngx.status = response.status
    for k, v in pairs(response.headers) do
        ngx.header[k] = v
    end

    ngx.print(response.body)
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