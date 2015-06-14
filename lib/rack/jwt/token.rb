module Rack
  module JWT
    class Token
      # TODO : Support all algorithms, not just default 'HS256'
      # https://github.com/progrium/ruby-jwt#algorithms-and-usage
      def self.encode(payload, secret)
        ::JWT.encode(payload, secret, 'HS256')
      end

      def self.decode(token, secret, verify, options)
        ::JWT.decode(token, secret, verify, options)
      rescue
        # It will raise an error if it is not a valid token due to any reason
        nil
      end
    end
  end
end
