require "rack/jwt/version"

module Rack
  module JWT
    autoload :Auth, 'rack/jwt/auth'
    autoload :Token, 'rack/jwt/token'
  end
end
