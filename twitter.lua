-- further reading http://bit.ly/ZAPboU, http://bit.ly/13mk8vZ
local conf = {
  entry_path    = "/auth/twitter",
  callback_path = "/auth/twitter/callback",
  scope         = "",
  fields        = "",
  app_id        = "",
  app_secret    = "",
  mobile        = false,
  uses          = 'oauth'
  api_host      = "https://api.twitter.com",
  oauth_host    = "https://api.twitter.com",
  

  --consumer_key = "AAAAAAAAAAAAAAAA", -- take that from your twitter app page
  --consumer_secret = "BBBBBBBBBBBBBBBB", -- take that from your twitter app page
  
  --      request_token_url = 'https://api.twitter.com/oauth/request_token',
  --      authorize_url= 'https://api.twitter.com/oauth/authorize',
  --      access_token_url= 'https://api.twitter.com/oauth/access_token',
  --      token_ready_url='http://example.org/oauth/token_ready'

  authorize_path     = '/oauth/authenticate'
  request_token_path = '/oauth/request_token'
  access_token_path  = '/oauth/access_token'

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

conf.user_params = function(self, ...)
    local access_token, access_token_secret = {...}
    return {
        url    = conf.api_host .. '/1.1/users/show.json',
        params = {access_token = access_token, access_token_secret = access_token_secret}
      }
  end

return conf