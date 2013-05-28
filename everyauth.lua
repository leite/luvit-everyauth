-- ----------------------------------------------------------------------------
-- "THE BEER-WARE LICENSE" (Revision 42):
-- <xxleite@gmail.com> wrote this file. As long as you retain this notice you
-- can do whatever you want with this stuff. If we meet some day, and you think
-- this stuff is worth it, you can buy me a beer in return
-- ----------------------------------------------------------------------------

local string    = require 'string'
local json      = require 'json'
local coroutine = require 'coroutine'
local http      = require 'musasaua'

local sub, gsub, format, find, byte, match, upper, len, parse, create, resume, yield 
    = string.sub, string.gsub, string.format, string.find, string.byte, string.match, string.upper,
      string.len, json.parse, coroutine.create, coroutine.resume, coroutine.yield

string, json, coroutine = nil, nil, nil

local everyauth, debug = {}, false
everyauth.__index = everyauth

local function debug(...)
  if debug then
    p(...)
  end
end

everyauth.auth_path                = '/oauth/authorize'
everyauth.access_token_path        = '/oauth/access_token'
everyauth.access_token_http_method = 'POST'
everyauth.oauth_coroutine          = nil

-- custom parser, luvit parse is not good
function everyauth:get_query(url)
  local results         =  {}
  local parse_query     =  function(key, value)
    if find(key, "%[%]")  ~= nil then
      key          = gsub(key, '%[%]', '')
      results[key] = results[key] and results[key] or {}
      insert(results[key], value)
    else
      results[key] = value
    end
  end
  gsub(url, "%/?%??([^&=]+)=?([^&=]*)&?", parse_query)
  return results
end

-- 
function everyauth:stringify_query(query_array)
  local function urlencode(str)
    if not str then
      return ''
    end
    return gsub(gsub(gsub(str, '\n', '\r\n'), '([^%w])', function(c) return format('%%%02X', byte(c)) end), ' ', '+')
  end
  local query = ''
  if query_array then
    for key, value in pairs(query_array) do
      query = query .. urlencode(key) ..'='.. urlencode(value) ..'&'
    end
  end
  return query
end

-- request oauth endpoint (url, callback, [params], [method], [headers], [timeout])
function everyauth:request(url, callback, ...)
  local args = {...}
  local params, method, timeout, headers = 
    (args[1] and (type(args[1])=='table'  and args[1] or {}   ) or {}),
    (args[2] and (type(args[2])=='string' and args[2] or 'GET') or 'GET'),
    (args[4] and (type(args[4])=='number' and args[4] or 20000) or 20000),
    (args[3] and (type(args[3])=='table'  and args[3] or {}   ) or {})

  local function parse_data(data)
    if not data then
      callback(true, nil)
      return
    end

    if sub(data.headers['content-type'], 1, 16)=='application/json' then
      callback(false, parse(data.body))
    elseif sub(data.headers['content-type'], 1, 10)=='text/plain' or sub(data.headers['content-type'], 1, 33)=='application/x-www-form-urlencoded' then
      callback(false, self:get_query(data.body))
    else
      callback(pcall(parse, data.body))  -- try to parse
    end
  end

  http.connection_timeout = timeout
  http.read_timeout       = timeout
  http:request({url = url, method = method, params = params, headers = headers}, parse_data)
end

-- 
function everyauth:get_auth_uri()
  -- copy default params
  local params        = {}
  params.client_id    = self.app_id
  params.redirect_uri = self.host_name .. self.callback_path
  -- merge parameters if so
  if self.auth_query_params then
    for key,value in pairs(self:auth_query_params()) do 
      params[key] = (type(value) == 'function' and value() or value) 
    end
  end
  -- stringify and join paths
  return (sub(self.auth_path, 0, 4)=='http' and self.auth_path or self.oauth_host .. self.auth_path) .."?".. self:stringify_query(params)
end

-- 
function everyauth:get_code(params)
  if self:auth_callback_did_err(params) then
    debug('get code :: fail')
    return self:handle_auth_callback_error(params)
  end

  if not params.code then
    error("Missing code in querystring. The url looks like " + req.url)
  end
  
  return params.code
end

-- 
function everyauth:get_access_token(code, callback)
  --
  local params = {
          client_id     = self.app_id,
          redirect_uri  = self.host_name .. self.callback_path,
          code          = code,
          client_secret = self.app_secret
        }

  -- merge parameters if so
  if self.access_token_params then
    for key, value in pairs(self:access_token_params()) do 
      params[key] = (type(value) == 'function' and value() or value) 
    end
  end

  --(url, callback, [params], [method], [headers], [timeout])
  self:request(
    (find(self.access_token_path, "://") and self.access_token_path or self.oauth_host .. self.access_token_path),
    callback,
    params,
    self.access_token_http_method,
    {['Connetion'] = 'Keep-Alive'}
  )
  
end

-- server side oauth authentication sequence
function everyauth:oauth_transaction(params)
  local code, status, data, user_params, err_callback 
    = nil, false, {}, {}, 
    function(data)
      if self.handle_auth_callback_error then
        self:handle_auth_callback_error(
          --{req = self.req, res = self.res}, 
          data)
      else
        error('Could not find a authentication error handler')
      end
      return true
    end

  -- get authentication code
  code = self:get_code(params)          
  -- get access token
  self:get_access_token(code, function(err, returned_data)
    debug('access token', err, returned_data)
    status = not err and (not returned_data.access_token and true or false) or err
    data   = returned_data
    resume(self.oauth_coroutine)
  end)
  -- yields until access token returns
  yield()
  if status then 
    return err_callback(data)
  end
  
  user_params = self:user_params(data.access_token)
  data.code   = code
  self:request(
    user_params.url,
    function(err, user_data)
      -- check for errors
      if self:auth_callback_did_err(user_data) then
        err_callback(user_data)
      else
        if self.find_or_create_user then
          self:find_or_create_user(
            --{req = self.req, res = self.res}, 
            data, user_data, err)
        else
          -- TODO: store in session?
          self.nxt()
        end
      end
    end,
    user_params.params,
    user_params.method
  )
  -- must add to session
end

function everyauth:middleware(options)

  options = options or {}
  for key, value in pairs(options) do
    self[key] = value or self[key]
  end

  return function(req, res, nxt)

    local params   = req.uri.search and self:get_query(req.uri.search) or {}
    self.req, self.res, self.nxt, self.host_name = req, res, nxt, "http://" .. req.headers.host

    p(self.entry_path, self.callback_path, req.uri.pathname, match(req.uri.pathname, self.entry_path), match(req.uri.pathname, self.callback_path))

    if match(req.uri.pathname, self.entry_path) then   
      -- request authentication
      res:send(302, nil, {['Location'] = self:get_auth_uri()}, true)
    elseif match(req.uri.pathname, self.callback_path) then  
      -- authentication callback
      self.oauth_coroutine = create(function() self:oauth_transaction(params) end)
      resume(self.oauth_coroutine)
    else
      nxt()
    end
  end
end

local function load_provider(key, args)
  local provider = require('./' .. key)
  local proxy    = setmetatable(provider, {__index = everyauth})
  return proxy
end

local providers_lookup = {}
providers_lookup = setmetatable(
  providers_lookup, 
  {
    __index = function (t, k)
      local v = load_provider(k, arg)
      t[k]    = v
      return v
    end
  }
)

return providers_lookup