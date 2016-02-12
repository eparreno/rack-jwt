module Rack
  module JWT
    class Token

      # abc123.abc123.abc123    (w/ signature)
      # abc123.abc123.          ('none')
      TOKEN_REGEX = /\A([a-zA-Z0-9\-\_\~\+\\]+\.[a-zA-Z0-9\-\_\~\+\\]+\.[a-zA-Z0-9\-\_\~\+\\]*)\z/

      def self.encode(payload, secret, alg = 'HS256')

        unless payload.is_a?(Hash)
          raise "Invalid payload. Must be a Hash."
        end

        unless secret.nil? ||
             secret.is_a?(String) ||
             secret.is_a?(OpenSSL::PKey::RSA) ||
             secret.is_a?(OpenSSL::PKey::EC)
          raise "Invalid secret. Must be a nil, String, OpenSSL::PKey::RSA, or OpenSSL::PKey::EC"
        end

        unless alg.is_a?(String)
          raise "Invalid algorithm. Must be a String."
        end

        unless Rack::JWT::Auth::SUPPORTED_ALGORITHMS.include?(alg)
          raise "Unsupported algorithm"
        end

        # if using an unsigned token ('none') you *must* set the `secret`
        # to `nil` in which case any user provided `secret` will be ignored.
        if alg == 'none'
          secret = nil
        end

        ::JWT.encode(payload, secret, alg)
      end

      def self.decode(token, secret, verify, options = {})

        # the token passed in must look valid
        unless token =~ TOKEN_REGEX
          raise "Invalid token format"
        end

        unless secret.nil? ||
             secret.is_a?(String) ||
             secret.is_a?(OpenSSL::PKey::RSA) ||
             secret.is_a?(OpenSSL::PKey::EC)
          raise "Invalid secret. Must be a nil, String, OpenSSL::PKey::RSA, or OpenSSL::PKey::EC"
        end

        # ensure verify is an actual `nil` or `false` intentionally,
        # otherwise set it to the sane default of `true` which is almost
        # always correct.
        unless verify.nil? || verify.is_a?(FalseClass)
          verify = true
        end

        # set a sane default algorithm if none was set
        if options[:algorithm].nil?
          options.merge!({ algorithm: 'HS256' })
        end

        # if using an unsigned 'none' algorithm token you *must* set the
        # `secret` to `nil` and `verify` to `false` or it won't work per
        # the ruby-jwt docs. Using 'none' is probably not recommended.
        if options[:algorithm] == 'none'
          secret = nil
          verify = false
        end

        unless Rack::JWT::Auth::SUPPORTED_ALGORITHMS.include?(options[:algorithm])
          raise "Unsupported algorithm"
        end

        ::JWT.decode(token, secret, verify, options)
      end

    end
  end
end
