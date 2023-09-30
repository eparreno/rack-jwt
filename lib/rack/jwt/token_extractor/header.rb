module Rack
  module JWT
    class TokenExtractor
      class Header
        def initialize(env)
          @env = env
        end

        # The last segment gets dropped for 'none' algorithm since there is no
        # signature so both of these patterns are valid. All character chunks
        # are base64url format and periods.
        #   Bearer abc123.abc123.abc123
        #   Bearer abc123.abc123.
        BEARER_TOKEN_REGEX = %r{
          ^Bearer\s{1}(       # starts with Bearer and a single space
          [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
          [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
          [a-zA-Z0-9\-\_]*    # 0 or more chars, no trailing chars
          )$
        }x

        def token
          @token ||= BEARER_TOKEN_REGEX.match(@env['HTTP_AUTHORIZATION'])[1]
        end

        def validate!
          if @env['HTTP_AUTHORIZATION'].nil? || @env['HTTP_AUTHORIZATION'].strip.empty?
            raise Error, 'Missing Authorization header'
          end

          if @env['HTTP_AUTHORIZATION'] !~ BEARER_TOKEN_REGEX
            raise Error, 'Invalid Authorization header format'
          end
        end
      end
    end
  end
end
