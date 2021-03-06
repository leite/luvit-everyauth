
-- specify types of access: http://bit.ly/14l8zEv, specify returned fields: http://bit.ly/14l8Kjn

local conf = { 
  entry_path    = "/auth/facebook",
  callback_path = "/auth/facebook/callback",
  scope         = "",
  fields        = "",
  app_id        = "",
  app_secret    = "",
  mobile        = false,

  api_host      = "https://graph.facebook.com",
  oauth_host    = "https://graph.facebook.com",
  auth_path     = "https://www.facebook.com/dialog/oauth",
  
  access_token_http_method = "GET",
  auth_callback_did_err    = function(self, params)
    return params and params.error
  end
}

conf.auth_query_params = function (self)
    return {scope = conf.scope}
  end

conf.access_token_params = function(self)
    return {}
  end

conf.user_params = function(self, access_token)
    return {url = conf.api_host .. '/me', params = {access_token = access_token, fields = conf.fields}}
  end

return conf