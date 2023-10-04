module Rack
  module JWT
    # Token encoding and decoding
    class Token
      # abc123.abc123.abc123    (w/ signature)
      # abc123.abc123.          ('none')
      TOKEN_REGEX = /\A([a-zA-Z0-9\-\_\~\+\\]+\.[a-zA-Z0-9\-\_\~\+\\]+\.[a-zA-Z0-9\-\_\~\+\\]*)\z/
      DEFAULT_HEADERS = {typ: 'JWT'}

      def self.encode(payload, secret, alg = 'HS256', headers = {})
        raise 'Invalid payload. Must be a Hash.' unless payload.is_a?(Hash)
        raise 'Invalid secret type.'             unless secret_of_valid_type?(secret)
        raise 'Unsupported algorithm'            unless algorithm_supported?(alg)

        headers = DEFAULT_HEADERS.merge(headers)

        # if using an unsigned token ('none' alg) you *must* set the `secret`
        # to `nil` in which case any user provided `secret` will be ignored.
        if alg == 'none'
          ::JWT.encode(payload, nil, alg, headers)
        else
          ::JWT.encode(payload, secret, alg, headers)
        end
      end

      def self.decode(token, secret, verify, options = {})
        raise 'Invalid token format.'     unless valid_token_format?(token)
        raise 'Invalid secret type.'      unless secret_of_valid_type?(secret)
        raise 'Unsupported verify value.' unless verify_of_valid_type?(verify)
        options[:algorithm] = 'HS256'     if options[:algorithm].nil?
        raise 'Unsupported algorithm'     unless algorithm_supported?(options[:algorithm])

        # If using an unsigned 'none' algorithm token you *must* set the
        # `secret` to `nil` and `verify` to `false` or it won't work per
        # the ruby-jwt docs. Using 'none' is probably not recommended.
        if options[:algorithm] == 'none'
          ::JWT.decode(token, nil, false, options)
        else
          ::JWT.decode(token, secret, verify, options)
        end
      end

      def self.secret_of_valid_type?(secret)
        secret.nil? ||
          secret.is_a?(String) ||
          secret.is_a?(OpenSSL::PKey::RSA) ||
          secret.is_a?(OpenSSL::PKey::EC)  ||
          (defined?(RbNaCl) && secret.is_a?(RbNaCl::Signatures::Ed25519::SigningKey)) ||
          (defined?(RbNaCl) && secret.is_a?(RbNaCl::Signatures::Ed25519::VerifyKey))
      end

      # Private Utility Class Methods
      # See : https://gist.github.com/Integralist/bb8760d11a03c88da151

      def self.valid_token_format?(token)
        token =~ TOKEN_REGEX
      end
      private_class_method :valid_token_format?

      def self.algorithm_supported?(alg)
        Rack::JWT::Auth::SUPPORTED_ALGORITHMS.include?(alg)
      end
      private_class_method :algorithm_supported?

      def self.verify_of_valid_type?(verify)
        verify.nil? || verify.is_a?(FalseClass) || verify.is_a?(TrueClass)
      end
      private_class_method :verify_of_valid_type?
    end
  end
end
