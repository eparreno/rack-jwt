require 'jwt'
require 'logger'

module Rack
  module JWT
    # Authentication middleware
    class Auth
      attr_reader :logger
      attr_reader :secret
      attr_reader :verify
      attr_reader :options
      attr_reader :exclude
      attr_reader :optional

      SUPPORTED_ALGORITHMS = %w(none HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512).freeze
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

      # Initialization should fail fast with an ArgumentError
      # if any args are invalid.
      def initialize(app, opts = {})
        @logger  = opts[:logger] || ::Logger.new(STDOUT)
        @app     = app
        @secret  = opts.fetch(:secret, nil)
        @verify  = opts.fetch(:verify, true)
        @options = opts.fetch(:options, {})
        @exclude = compile_patterns!(opts.fetch(:exclude, []))
        @optional = compile_patterns!(opts.fetch(:optional, []))
        @secret  = @secret.strip if @secret.is_a?(String)
        @options[:algorithm] = DEFAULT_ALGORITHM if @options[:algorithm].nil?

        check_secret_type!
        check_secret!
        check_secret_and_verify_for_none_alg!
        check_verify_type!
        check_options_type!
        check_valid_algorithm!
      end

      def call(env)
        if path_is_excluded?(env)
          @app.call(env)
        elsif missing_auth_header?(env)
          if path_is_optional?(env)
            @app.call(env)
          else
            # note: no need for warning log message on this, it happens all
            # the time when bots are fishing around the site for entry. Adds
            # too much noise to logs.
            return_error('Missing Authorization header', log_level: :debug)
          end
        elsif invalid_auth_header?(env)
          return_error('Invalid Authorization header format')
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
          decoded_token = Token.decode(token, @secret, @verify, @options)
          env['jwt.header'] = decoded_token.last
          env['jwt.payload'] = payload = decoded_token.first
          if payload.is_a?(Hash)
            Thread.current[:jwt_sub] = payload['sub']
          end
          result = @app.call(env)
          Thread.current[:jwt_sub] = nil
          result
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

      end

      def check_secret_type!
        unless @secret.nil? ||
               @secret.is_a?(String) ||
               @secret.is_a?(OpenSSL::PKey::RSA) ||
               @secret.is_a?(OpenSSL::PKey::EC)
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

      # Compile the list of patterns provided by the user. Each regex is left
      # as is, each string is turned into the regex equivalent of #start_with?
      def compile_patterns!(patterns)
        if patterns.is_a?(Hash)
          patterns = [*patterns]
        elsif !patterns.is_a?(Array)
          raise ArgumentError, 'patterns argument must be an Array or Hash'
        end
        patterns.map do |arr|
          # convert shorthand `:exclude => ['/path']` to `:exclude => { '/path' => {} }`
          arr = [arr, {}] unless arr.is_a?(Array)
          [
            compile_path_pattern(arr[0]),
            compile_http_method_pattern(arr[1])
          ]
        end
      end

      def compile_path_pattern(pattern)
        return pattern if pattern.is_a?(Regexp)

        unless pattern.is_a?(String)
          raise ArgumentError.new("Path pattern must be a string or regexp. Received #{pattern.class} '#{pattern}'")
        end
        unless pattern.start_with?('/')
          raise ArgumentError.new("Cannot use '#{pattern}' as a pattern: string pattern must start with '/'")
        end
        if (rgx = Regexp.compile(pattern) rescue nil).nil?
          raise ArgumentError.new("Could not compile '#{pattern}' to regex")
        end

        rgx
      end

      def compile_http_method_pattern(pattern)
        # allow only empty hash to disable method verification
        return nil if ([{}].include?(pattern))

        # convert shorthand `'/path' => :get` to `'/path' => { :only => [:get] }`
        pattern = { only: [pattern] } if ( pattern.is_a?(Symbol) || pattern.is_a?(String) )

        if !pattern.is_a?(Hash)
          raise ArgumentError.new("Method spec must be a hash of type {except: [...], only: [...]}. Received #{pattern.class} '#{pattern}'")
        end

        %i[only except].each_with_object({}) do |key, hash|
          next unless pattern.key?(key)
          val = pattern[key]

          # convert shorthand `{ :only => :get }` to `{ :only => [:get] }`
          val = [val] if ( val.is_a?(Symbol) || val.is_a?(String) )

          unless val.is_a?(Array)
            raise ArgumentError.new("Method list must be an array. Received val '#{val}'")
          end
          hash[key] = val.map { |v| v.to_s.upcase }
        end
      end

      def path_is_excluded?(env)
        path_matches_pattern?(env['PATH_INFO'], env['REQUEST_METHOD'], @exclude)
      end

      def path_is_optional?(env)
        path_matches_pattern?(env['PATH_INFO'], env['REQUEST_METHOD'], @optional)
      end

      def path_matches_pattern?(path, method, patterns)
        patterns.any? do |pattern|
          next false unless path =~ /#{pattern[0]}/
          next true if pattern[1].nil?

          only = pattern[1][:only]
          except = pattern[1][:except]
          (only.nil? || only.include?(method)) &&
          (except.nil? || !except.include?(method))
        end
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

      def return_error(message, log_level: :warn)
        logger.send(log_level, "rack-jwt: #{message}")
        body    = { error: { message: message, status: 401 } }.to_json
        headers = { 'Content-Type' => 'application/json', 'Content-Length' => body.bytesize.to_s }

        [401, headers, [body]]
      end
    end
  end
end
