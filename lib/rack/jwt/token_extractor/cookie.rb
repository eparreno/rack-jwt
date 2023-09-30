module Rack
  module JWT
    class TokenExtractor
      class Cookie
        def initialize(env, cookie)
          @cookie = cookie
          @env = env
        end

        def token
          @token ||= parsed_cookie[@cookie]
        end

        def parsed_cookie
          @parsed_cookie ||= Rack::Utils.parse_cookies(@env)
        end

        def validate!
          parsed_cookie[@cookie] || raise(Error, 'Missing auth cookie')
        end
      end
    end
  end
end
