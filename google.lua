-- further reading http://bit.ly/14l81i8, http://bit.ly/12ou8JZ, http://bit.ly/12oufFo
local conf = {
  entry_path    = "/auth/google",
  callback_path = "/auth/google/callback",
  scope         = "",
  fields        = "",
  app_id        = "",
  app_secret    = "",
  mobile        = false,

  api_host      = "https://accounts.google.com",
  oauth_host    = "https://accounts.google.com",
  auth_path     = "/o/oauth2/auth",
  
  access_token_path     = '/o/oauth2/token',
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
        url    = 'https://www.googleapis.com/oauth2/v1/userinfo', 
        params = {access_token = access_token, alt = 'json'}
      }
  end

--[[
  .addToSession( function (sess, auth) {
    this._super(sess, auth);
    if (auth.refresh_token) {
      sess.auth[this.name].refreshToken = auth.refresh_token;
      sess.auth[this.name].expiresInSeconds = parseInt(auth.expires_in, 10);
    }
  })
--]]

return conf