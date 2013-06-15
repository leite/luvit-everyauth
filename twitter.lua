-- further reading http://bit.ly/ZAPboU, http://bit.ly/13mk8vZ
local conf = {
  entry_path    = "/auth/twitter",
  callback_path = "/auth/twitter/callback",
  scope         = "",
  fields        = "",
  app_id        = "",
  app_secret    = "",
  mobile        = false,

  api_host      = "https://api.twitter.com",
  oauth_host    = "https://api.twitter.com",
  auth_path     = "/oauth2/token",
  
  access_token_path     = '/oauth2/token',
  auth_callback_did_err = function(self, params)
    return params and params.error
  end
}

conf.auth_query_params = function (self)
    return {
        access_type     = 'offline', 
        approval_prompt = 'force',
        response_type   = 'code',
        scope           = conf.scope
      }
  end

conf.access_token_params = function(self)
    return {grant_type = 'authorization_code'}
  end

conf.user_params = function(self, access_token)
    return {
        url    = conf.api_host .. '/1.1/users/show.json',
        params = {access_token = access_token}
      }
  end

return conf