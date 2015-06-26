module Rack
  module JWT
    class Token
      def self.encode(payload, secret)
        ::JWT.encode(payload, secret)
      end

      def self.decode(token, secret)
        ::JWT.decode(token, secret)
      end
    end
  end
end
