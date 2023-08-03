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
local plugin_name = "api2-plugin"

-- Define the plugin schema format
local plugin_schema = {
    type = "object",
    properties = {
        ep = {
            type = "object",
            items = {
                type = "object",
                properties = {
                    url = {
                        type = "string",
                        minLength = 1
                    },
                    ssl_verify = {
                        type = "boolean",
                        default = false,
                    },
                    timeout = {
                        type = "integer",
                        minimum = 1,
                        maximum = 60000,
                        default = 3000,
                        description = "timeout in milliseconds",
                    },
                    keepalive = {type = "boolean", default = true},
                    keepalive_timeout = {type = "integer", minimum = 1000, default = 60000},
                    keepalive_pool = {type = "integer", minimum = 1, default = 5},
                },
                required = {"url"},
            },
        },
    },
}

-- Defining a shared_dict
local shared_dict = ngx.shared.my_shared_dict

-- Cleaning shared_dict
local function clear_shared_dict(key_name_shared_dict)
    local keys = shared_dict:get_keys()
    for _, key in ipairs(keys) do
        if key == key_name_shared_dict then
            shared_dict:delete(key)
        end
    end
end

-- Define the plugin with its version, priority, name, and schema
local _M = {
    version = 1.0,
    priority = -1000,
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

local function is_odd(number)
    return number % 2 == 1
end

-- Function to be called during the access phase
--function _M.rewrite(conf, ctx)
function _M.access(conf, ctx)
--function _M.before_proxy(conf, ctx)
--function _M.header_filter(conf, ctx)
--function _M.body_filter(conf, ctx)

    -- Retrieve the data from the shared dictionary (set by previous plugin, i.e. api1-plugin)
    local previous_api_response_body = shared_dict:get("my_api_response_body")
    local previous_resp_data, previous_resp_id_value
    if previous_api_response_body ~= nil then
        core.log.error("2nd Plugin * There is info in the shared-dict")
        previous_resp_data = cjson.decode(previous_api_response_body)

        -- Printing the "id" value of api1-plugin response
        previous_resp_id_value = previous_resp_data["id"]
        if previous_resp_id_value ~= nil then
            core.log.error("2nd Plugin * Printing ID from previous response: ", previous_resp_id_value)
        else
            core.log.error("2nd Plugin * The ID from previous response is NULL")
        end 
    else
        core.log.error("2nd Plugin * The shared-dict is NULL")
    end 

    local last_resp, err
    -- assembly request parameters
    local params = {
        method = core.request.get_method(),
        query = core.request.get_uri_args(),
        ssl_verify = conf.ep.ssl_verify,
        keepalive = conf.ep.keepalive,
        headers = ngx.req.get_headers(),
    }

    -- attaching connection pool configuration
    if conf.ep.keepalive then
        params.keepalive_timeout = conf.ep.keepalive_timeout
        params.keepalive_pool = conf.ep.keepalive_pool
    end

    -- initialize new http connection
    local httpc = http.new()
    httpc:set_timeout(conf.ep.timeout)

    -- if last_resp ~= nil then
    --     -- setup body from last success response
    --     params.method = "POST"
    --     params.body = last_resp.body
    -- else
    --     -- setup header, query and body for first request (upstream)
    --     params.method = core.request.get_method()
    --     params.query = core.request.get_uri_args()
    --     -- params.method = "POST"
    --     -- params.query = ""
    --     params.headers = core.request.headers()
    --     local body, err = core.request.get_body()
    --     if err then
    --         return 503
    --     end
    --     if body then
    --         params.body = body
    --     end
    -- end

    -- Calling new EndPoint URL
    local upstream_url_fin
    if previous_resp_id_value == nil then
        core.log.error("2nd Plugin * The ID is NULL, We will call the Random Appliances API")
        upstream_url_fin = "https://random-data-api.com/api/v2/appliances"        
    elseif is_odd(tonumber(previous_resp_id_value)) then
        core.log.error("2nd Plugin * The ID is odd, We will call the Random BloodTypes API")
        --return 404, "The ID is odd"
        upstream_url_fin = "https://random-data-api.com/api/v2/blood_types"
    else 
        core.log.error("2nd Plugin * The ID is even, We will call the Random Banks API")
        upstream_url_fin = conf.ep.url
    end

    -- Make the request to the specified URL
    -- send request to each node and temporary store response
    --last_resp, err = httpc:request_uri(conf.ep.url, params)
    last_resp, err = httpc:request_uri(upstream_url_fin, params)

    core.log.error("2nd Plugin * 11111111")

    if not last_resp then
        core.log.error("2nd Plugin * 22222222222", "Failed when requesting ", conf.ep.url, ", error: ", err)
        return 500, "request failed: " .. err
    end

    core.log.error("2nd Plugin * 33333333333333")

    -- Forward the response status, headers, and body back to the client
    for k, v in pairs(last_resp.headers) do
        -- Avoid setting Transfer-Encoding and Connection,
        -- they can be broken for response headers.
        local lower_key = string.lower(k)
        if lower_key == "transfer-encoding"
            or lower_key == "connection" then
            goto continue
        end
        -- set response header
        core.response.set_header(k, v)
        ::continue::
    end

    core.log.error("2nd Plugin * 44444444")
    core.log.error("2nd Plugin * conf.ep.url: ", conf.ep.url)
    core.log.error("2nd Plugin * response.status: ", last_resp.status)
    core.log.error("2nd Plugin * response.body: ", last_resp.body)

    -- Store/override the api response body in a shared dictionary
    clear_shared_dict("my_api_response_body")
    shared_dict:set("my_api_response_body", last_resp.body)

    core.log.error("2nd Plugin * 555555555")

    return 200, last_resp.body
end


-- Function to be called during the log phase
function _M.log(conf, ctx)
    -- Log the plugin configuration and the request context
    core.log.warn("conf: ", core.json.encode(conf))
    --core.log.warn("ctx: ", core.json.encode(ctx, true))
end

-- Return the plugin so it can be used by APISIX
return _M