module Rack
  module JWT
    class Token
      def self.encode(payload, secret)
        ::JWT.encode(payload, secret)
      end

      def self.decode(token, secret)
        ::JWT.decode(token, secret)
      rescue
        # It will raise an error if it is not a valid token due to any reason
        nil
      end
    end
  end
end
