require 'jwt'

module Rack
  module JWT
    # Authentication middleware
    class Auth
      attr_reader :secret
      attr_reader :verify
      attr_reader :options
      attr_reader :exclude

      SUPPORTED_ALGORITHMS = [
        'none',
        'HS256',
        'HS384',
        'HS512',
        'RS256',
        'RS384',
        'RS512',
        'ES256',
        'ES384',
        'ES512',
        ('ED25519' if defined?(RbNaCl)),
      ].compact.freeze

      DEFAULT_ALGORITHM = 'HS256'.freeze

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

      JWT_ERRORS = [
        ::JWT::EncodeError,
        ::JWT::DecodeError,
        ::JWT::VerificationError,
        ::JWT::ExpiredSignature,
        ::JWT::IncorrectAlgorithm,
        ::JWT::ImmatureSignature,
        ::JWT::InvalidIssuerError,
        ::JWT::InvalidIatError,
        ::JWT::InvalidAudError,
        ::JWT::InvalidSubError,
        ::JWT::InvalidJtiError,
        ::JWT::InvalidPayload,
      ].freeze

      MissingAuthHeader = Class.new(StandardError)
      InvalidAuthHeaderFormat = Class.new(StandardError)

      ERRORS_TO_RESCUE = (JWT_ERRORS + [MissingAuthHeader, InvalidAuthHeaderFormat]).freeze

      # Initialization should fail fast with an ArgumentError
      # if any args are invalid.
      def initialize(app, opts = {})
        @app     = app
        @secret  = opts.fetch(:secret, nil)
        @verify  = opts.fetch(:verify, true)
        @options = opts.fetch(:options, {})
        @exclude = opts.fetch(:exclude, [])

        # TODO: Validate that on_error is callable.
        @on_error = opts.fetch(:on_error, &method(:default_on_error))

        @secret = @secret.strip if @secret.is_a?(String)
        @options[:algorithm] = DEFAULT_ALGORITHM if @options[:algorithm].nil?

        check_secret_type!
        check_secret!
        check_secret_and_verify_for_none_alg!
        check_verify_type!
        check_options_type!
        check_valid_algorithm!
        check_exclude_type!
      end

      def call(env)
        if path_matches_excluded_path?(env)
          @app.call(env)
        else
          verify_token(env)
        end
      end

      private

      def verify_token(env)
        # extract the token from the Authorization: Bearer header
        # with a regex capture group.
        token = BEARER_TOKEN_REGEX.match(env['HTTP_AUTHORIZATION'])[1]

        begin
          raise MissingAuthHeader if missing_auth_header?(env)
          raise InvalidAuthHeaderFormat if invalid_auth_header?(env)

          decoded_token = Token.decode(token, @secret, @verify, @options)
          env['jwt.payload'] = decoded_token.first
          env['jwt.header'] = decoded_token.last
          @app.call(env)
        rescue *ERRORS_TO_RESCUE => e
          @on_error.call(e)
        end
      end

      def check_secret_type!
        unless Token.secret_of_valid_type?(@secret)
          raise ArgumentError, 'secret argument must be a valid type'
        end
      end

      def check_secret!
        if @secret.nil? || (@secret.is_a?(String) && @secret.empty?)
          unless @options[:algorithm] == 'none'
            raise ArgumentError, 'secret argument can only be nil/empty for the "none" algorithm'
          end
        end
      end

      def check_secret_and_verify_for_none_alg!
        if @options && @options[:algorithm] && @options[:algorithm] == 'none'
          unless @secret.nil? && @verify.is_a?(FalseClass)
            raise ArgumentError, 'when "none" the secret must be "nil" and verify "false"'
          end
        end
      end

      def check_verify_type!
        unless verify.is_a?(TrueClass) || verify.is_a?(FalseClass)
          raise ArgumentError, 'verify argument must be true or false'
        end
      end

      def check_options_type!
        raise ArgumentError, 'options argument must be a Hash' unless options.is_a?(Hash)
      end

      def check_valid_algorithm!
        unless @options &&
               @options[:algorithm] &&
               SUPPORTED_ALGORITHMS.include?(@options[:algorithm])
          raise ArgumentError, 'algorithm argument must be a supported type'
        end
      end

      def check_exclude_type!
        unless @exclude.is_a?(Array)
          raise ArgumentError, 'exclude argument must be an Array'
        end

        @exclude.each do |x|
          unless x.is_a?(String)
            raise ArgumentError, 'each exclude Array element must be a String'
          end

          if x.empty?
            raise ArgumentError, 'each exclude Array element must not be empty'
          end

          unless x.start_with?('/')
            raise ArgumentError, 'each exclude Array element must start with a /'
          end
        end
      end

      def path_matches_excluded_path?(env)
        @exclude.any? { |ex| env['PATH_INFO'].start_with?(ex) }
      end

      def valid_auth_header?(env)
        env['HTTP_AUTHORIZATION'] =~ BEARER_TOKEN_REGEX
      end

      def invalid_auth_header?(env)
        !valid_auth_header?(env)
      end

      def missing_auth_header?(env)
        env['HTTP_AUTHORIZATION'].nil? || env['HTTP_AUTHORIZATION'].strip.empty?
      end

      def default_on_error(error)
        error_message = {
          # TODO: What do we do with EncodeError.
          ::JWT::EncodeError => 'Invalid JWT token : Encode Error',
          ::JWT::DecodeError => 'Invalid JWT token : Decode Error',
          ::JWT::VerificationError => 'Invalid JWT token : Signature Verification Error',
          ::JWT::ExpiredSignature => 'Invalid JWT token : Expired Signature (exp)',
          ::JWT::IncorrectAlgorithm => 'Invalid JWT token : Incorrect Key Algorithm',
          ::JWT::ImmatureSignature => 'Invalid JWT token : Immature Signature (nbf)',
          ::JWT::InvalidIssuerError => 'Invalid JWT token : Invalid Issuer (iss)',
          ::JWT::InvalidIatError => 'Invalid JWT token : Invalid Issued At (iat)',
          ::JWT::InvalidAudError => 'Invalid JWT token : Invalid Audience (aud)',
          ::JWT::InvalidSubError => 'Invalid JWT token : Invalid Subject (sub)',
          ::JWT::InvalidJtiError => 'Invalid JWT token : Invalid JWT ID (jti)',
          ::JWT::InvalidPayload => 'Invalid JWT token : Invalid Payload',
          MissingAuthHeader => 'Missing Authorization header',
          InvalidAuthHeaderFormat => 'Invalid Authorization header format'
        }
        message = error_message.fetch(error.class, 'Default')
        body    = { error: message }.to_json
        headers = { 'Content-Type' => 'application/json', 'Content-Length' => body.bytesize.to_s }

        [401, headers, [body]]
      end
    end
  end
end
