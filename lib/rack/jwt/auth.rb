require 'jwt'
require 'rack/jwt/token_extractor'
require 'rack/jwt/token_extractor/header'
require 'rack/jwt/token_extractor/cookie'

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

      # Initialization should fail fast with an ArgumentError
      # if any args are invalid.
      def initialize(app, opts = {})
        @app            = app
        @secret         = opts.fetch(:secret, nil)
        @token_location = opts.fetch(:token_location, :header)
        @verify         = opts.fetch(:verify, true)
        @options        = opts.fetch(:options, {})
        @exclude        = opts.fetch(:exclude, [])

        @secret  = @secret.strip if @secret.is_a?(String)
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
        token_extractor = TokenExtractor.for(env, @token_location)
        token_extractor.validate!

        decoded_token = Token.decode(token_extractor.token, @secret, @verify, @options)
        env['jwt.payload'] = decoded_token.first
        env['jwt.header'] = decoded_token.last
        @app.call(env)
      rescue TokenExtractor::Error => e
        return_error(e.message)
      rescue ::JWT::VerificationError
        return_error('Invalid JWT token : Signature Verification Error')
      rescue ::JWT::ExpiredSignature
        return_error('Invalid JWT token : Expired Signature (exp)')
      rescue ::JWT::IncorrectAlgorithm
        return_error('Invalid JWT token : Incorrect Key Algorithm')
      rescue ::JWT::ImmatureSignature
        return_error('Invalid JWT token : Immature Signature (nbf)')
      rescue ::JWT::InvalidIssuerError
        return_error('Invalid JWT token : Invalid Issuer (iss)')
      rescue ::JWT::InvalidIatError
        return_error('Invalid JWT token : Invalid Issued At (iat)')
      rescue ::JWT::InvalidAudError
        return_error('Invalid JWT token : Invalid Audience (aud)')
      rescue ::JWT::InvalidSubError
        return_error('Invalid JWT token : Invalid Subject (sub)')
      rescue ::JWT::InvalidJtiError
        return_error('Invalid JWT token : Invalid JWT ID (jti)')
      rescue ::JWT::DecodeError
        return_error('Invalid JWT token : Decode Error')
      end

      def check_secret_type!
        unless Token.secret_of_valid_type?(@secret)
          raise ArgumentError, 'secret argument must be a valid type'
        end
      end

      def check_secret!
        if @secret.nil? || (@secret.is_a?(String) && @secret.empty?)
          if @options[:algorithm] != 'none' && @options[:jwks].nil?
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
          unless x.is_a?(String) || x.is_a?(Regexp)
            raise ArgumentError, 'each exclude Array element must be a String or a Regexp'
          end

          if x.to_s.empty?
            raise ArgumentError, 'each exclude Array element must not be empty'
          end

          # Perhaps surprisingly, Regexp#inspect actually produces the more
          # natural version of the string than #to_s.
          as_s = x.is_a?(Regexp) ? x.inspect : x
          unless as_s.start_with?('/')
            raise ArgumentError, 'each exclude Array element must start with a /'
          end
        end
      end

      def path_matches_excluded_path?(env)
        @exclude.any? do |ex|
          if ex.is_a?(Regexp)
            ex.match?(env['PATH_INFO'])
          else
            env['PATH_INFO'].start_with?(ex)
          end
        end
      end

      def return_error(message)
        body    = { error: message }.to_json
        headers = { 'Content-Type' => 'application/json' }

        [401, headers, [body]]
      end
    end
  end
end
