# Summary

luvit-everyauth is a authentication and authorization (password, facebook, google & more) for your luvit app.

# Help and Support

Please fill an issue or help it doing a clone and then a pull request

# License

[BEER-WARE](http://en.wikipedia.org/wiki/Beerware), see source
  
# Basic usage

```lua

    local app    = require('luvit-app'):new()
    local json   = require 'json'
    local auth  = require 'luvit-everyauth'

    local headers   = {['Content-type'] = 'application/json;charset=utf-8'}
    local stringify = json.stringify

    -- static files
    app:mount('/', 'static', {mount = '', root = __dirname .. '/img'})
    -- luvit-everyauth 
    app:use(auth.facebook:middleware({
        app_id     = "181514099999999", 
        app_secret = "8a50402a694ee6axxxxXXXXXXxxxxxxx",
        scope      = "email,user_about_me,user_birthday", 
        fields     = "id,birthday,name,gender,email",
        handle_auth_callback_error = function(self, data)
          self.res:send(200, stringify(data), headers, true)
        end,
        find_or_create_user = function(self, data, user_data, err)
          self.res:send(200, stringify({data = data, user = user_data}), headers, true)
        end
      }))

    app:run(8282, '127.0.0.1')

``` 

# Tests

... in progress

# TODO

+ add support to google & password
+ support luvit module style
+ create a test suite
+ create a wiki?

% February 17th, 2013 -03 GMT