module Rack
  module JWT
    class TokenExtractor
      class Error < StandardError; end

      def self.for(env, token_location)
        case token_location
        in :header
          Header.new(env)
        in { cookie: }
          Cookie.new(env, cookie)
        else
          raise ArgumentError, 'token_source option must be :header or :cookie'
        end
      end
    end
  end
end
