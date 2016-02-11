require 'jwt'

module Rack
  module JWT
    class Auth

      # The Authorization: Bearer token format per RFC6750
      # http://tools.ietf.org/html/rfc6750#section-2.1
      TOKEN_REGEX = /\ABearer ([a-zA-Z0-9\-\_\~\+\\]+\.[a-zA-Z0-9\-\_\~\+\\]+\.[a-zA-Z0-9\-\_\~\+\\]+)\z/

      def initialize(app, opts = {})
        @app          = app
        @jwt_secret   = opts.fetch(:secret)
        @jwt_verify   = opts.fetch(:verify, true)
        @jwt_options  = opts.fetch(:options, {})
        @exclude      = opts.fetch(:exclude, [])
      end

      def call(env)
        if path_matches_excluded_path?(env)
          @app.call(env)
        elsif missing_auth_header?(env)
          return_error('Missing Authorization header')
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
        token = TOKEN_REGEX.match(env['HTTP_AUTHORIZATION'])[1]

        begin
          decoded_token = Token.decode(token, @jwt_secret, @jwt_verify, @jwt_options)
          env['jwt.payload'] = decoded_token.first
          env['jwt.header'] = decoded_token.last
          @app.call(env)
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

      def path_matches_excluded_path?(env)
        @exclude.any? {|ex| env['PATH_INFO'].start_with?(ex)}
      end

      def valid_auth_header?(env)
        env['HTTP_AUTHORIZATION'] =~ TOKEN_REGEX
      end

      def invalid_auth_header?(env)
        !valid_auth_header?(env)
      end

      def missing_auth_header?(env)
        env['HTTP_AUTHORIZATION'].nil? || env['HTTP_AUTHORIZATION'].strip.empty?
      end

      def return_error(message)
        body    = { error: message }.to_json
        headers = { 'Content-Type' => 'application/json',
          'Content-Length' => body.bytesize.to_s }

        [401, headers, [body]]
      end
    end
  end
end
