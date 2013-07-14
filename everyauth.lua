-- ----------------------------------------------------------------------------
-- "THE BEER-WARE LICENSE" (Revision 42):
-- <xxleite@gmail.com> wrote this file. As long as you retain this notice you
-- can do whatever you want with this stuff. If we meet some day, and you think
-- this stuff is worth it, you can buy me a beer in return
-- ----------------------------------------------------------------------------

-- i had lots of inspiration from: 
-- lua-oauth (https://github.com/DracoBlue/lua-oauth)
-- everyauth (https://github.com/bnoguchi/everyauth)

local s, t, js, c, http, m, o, hx, b64 =
      require('string'), require('table'), require('json'), require('coroutine'),
      require('musasaua'), require('math'), require('os'), require('_crypto').hmac, require('luvit-base64')

local sub, gsub, format, find, byte, match, upper, len, char, parse, create, resume, yield, digest, random, seed, time, insert, sort, enc64, dec64 = 
      s.sub, s.gsub, s.format, s.find, s.byte, s.match, s.upper, s.len, s.char, js.parse, c.create, c.resume, c.yield, hx.digest, m.random,
      m.randomseed, o.time, t.insert, t.sort, b64.encode, b64.decode

s, m, js, c, m, o, hx, b64 = nil, nil, nil, nil, nil, nil, nil, nil

local oauth_params = {
    oauth_consumer_key     = true,
    oauth_nonce            = true,
    oauth_signature_method = true,
    oauth_token            = true,
    oauth_verifier         = true,
    oauth_timestamp        = true,
    oauth_callback         = true,
    oauth_version          = true,
    scope                  = true
  }

-- basic functions
local function encode_hexa(c)
  return format('%%%02X', byte(c))
end

local function decode_hexa(c)
  return char(tonumber(c, 16))
end

local function sort_it(a, b)
  return a.k==b.k and (a.v<b.v) or (a.k<b.k)
end

local function sha1(...)
  local args = ...
  return digest('sha1', args[1], args[2], args[3])
end

local function nonce()
  seed(time())
  return sha1(tostring(random()) .. 'random' .. tostring(time()), 'keyyyy')
end

local function encode_param(str)
  if not str then
    return ''
  end
  return gsub(gsub(gsub(str, '\n', '\r\n'), '([^%w])', encode_hexa), ' ', '+') --([^-%._~%w])
end

local function decode_param(str)
  if not str then
    return ''
  end
  return gsub(gsub(gsub(str, '+', ' '), '%%(%x%x)', decode_hexa), "\r\n", "\n")
end

local everyauth, debug = {}, false
everyauth.__index = everyauth

local function debug(...)
  if debug then
    p(...)
  end
end

everyauth.uses                     = 'oauth2'               -- default oauth2
everyauth.auth_path                = '/oauth/authorize'     -- oauth2
everyauth.access_token_path        = '/oauth/access_token'  -- oauth/oauth2
everyauth.access_token_http_method = 'POST'                 
everyauth.authorize_path           = '/oauth/authenticate'  -- oauth
everyauth.request_token_path       = '/oauth/request_token' -- oauth 
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

-- oauth way self:stringify_query({k,v}) >>> returns query string
-- oauth2 way self:stringify_query({k,v}, true) >>> returns query headers, query string and all params
-- stringfy a hash o query values (query_hash, [sort and sort_out])
function everyauth:stringify_query(...)
  local query, query_array, sort_sort_out = '', ...
  if not query_array then
    return query
  end
    --
  if sort_sort_out then
    local _query_table, query_params, all_params = {}, '', ''
    --
    for key, value in pairs(query_array) do
      insert(
        _query_table, 
        {
          k = encode_param(key),
          v = encode_param(value)
        })
    end
    --
    sort(_query_table, sort_it)
    -- 
    for i=1, #_query_table do

      if oauth_params[_query_table[i].k] then
        query = format('%s%s="%s", ', query, _query_table[i].k, _query_table[i].v)
      else
        query_params = format('%s%s=%s&', query_params, _query_table[i].k, _query_table[i].v)
      end
      all_params = format('%s%s=%s&', all_params, _query_table[i].k, _query_table[i].v)
    end
    return sub(query, 1, -3), 
           sub(query_params, 1, -2), 
           sub(all_params, 1, -2)
  end
  --
  for key, value in pairs(query_array) do
    query = format('%s%s=%s&', query, encode_param(key), encode_param(value))
  end
  return sub(query, 1, -2)
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
    p('returning ...')
    --p(data)
    if not data then
      callback(true, nil)
      return
    end

    if sub(data.headers['content-type'], 1, 16)=='application/json' then
      callback(false, parse(data.body or data.data))
    elseif sub(data.headers['content-type'], 1, 10)=='text/plain' or sub(data.headers['content-type'], 1, 33)=='application/x-www-form-urlencoded' then
      callback(false, self:get_query(data.body or data.data))
    else
      callback(pcall(parse, data.body or data.data))  -- try to parse
    end
  end

  p('request ...')

  local xhttp = http:new()
  xhttp.connection_timeout = timeout
  xhttp.read_timeout       = timeout
  xhttp:request({url = url, method = method, params = params, headers = headers}, parse_data)
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
  if not params.code or self:auth_callback_did_err(params) then
    debug('get code :: fail')
    return self:handle_auth_callback_error(params)
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

function everyauth:get_oauth_sign(params)
  --
  local token_secret, method, headers, url, auth_query, query_params, all_query_params, hmac_b64 =
        (params.oauth_token_secret or ''), (params.method or 'GET'), (params.headers or {}), params.url, '', '', '', ''
  
  --
  params.oauth_signature_method = params.oauth_signature_method or 'HMAC-SHA1'
  params.url, params.method, params.oauth_token_secret, params.headers = nil, nil, nil, nil

  -- returns query headers, query string and all params
  auth_query, query_params, all_query_params = self:stringify_query(params, true)

  -- 
  hmac_b64 = enc64(
              sha1(
                format(
                  "%s&%s&%s", 
                  method, 
                  encode_param(url), 
                  all_query_params
                ),
                format(
                  "%s&%s", 
                  encode_param(self.app_secret), 
                  encode_param(token_secret)
                ),
                true
              ))
  
  --
  insert(
    headers, 
    format(
      'Authorization: OAuth "%s", oauth_signature="%s"',
      auth_query,
      encode_parameter(hmac_b64)
    ))

  return (method=='GET' and url ..'?' or '') .. (len(query_params)>3 and query_params or ''), headers
end

function everyauth:oauth_transaction(params)

end

-- server side oauth2 authentication sequence
function everyauth:oauth2_transaction(params)
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

    p('get code')
  -- get authentication code
  code = self:get_code(params) 

  p('code fetched', code)         
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

    --p(req.uri)
    --p(self.entry_path, self.callback_path, req.uri.pathname, match(req.uri.pathname, self.entry_path), match(req.uri.pathname, self.callback_path))

    if match(req.uri.pathname, self.entry_path..'/?$') then   
      -- request authentication
      p(' entry path match ... '.. self.entry_path)
      res:send(302, nil, {['Location'] = self:get_auth_uri()}, true)
    elseif match(req.uri.pathname, self.callback_path..'/?$') then  
      -- authentication callback
      p(' callback path match ... '.. self.callback_path)
      
      self.oauth_coroutine = self.uses=='oauth' and
                             create(function() self:oauth_transaction(params) end) or
                             create(function() self:oauth2_transaction(params) end)
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