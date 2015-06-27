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
      end
    end
  end
end
