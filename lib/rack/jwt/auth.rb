require 'jwt'

module Rack
  module JWT
    class Auth
      def initialize(app, opts = {})
        @app      = app
        @secret   = opts.fetch(:secret)
        @exclude  = opts.fetch(:exclude, [])
      end

      def call(env)
        if @exclude.include? env['PATH_INFO']
          @app.call(env)
        else
          check_jwt_token(env)
        end
      end

      private

      def check_jwt_token(env)
        if valid_header?(env)
          begin
            token = env['HTTP_AUTHORIZATION'].split(' ')[-1]
            decoded_token = Token.decode(token, @secret)
            env['jwt.header']  = decoded_token.last
            env['jwt.payload'] = decoded_token.first
            @app.call(env)
          rescue ::JWT::DecodeError
            return_error('Invalid JWT token')
          end
        else
          return_jwt_header_error(env)
        end
      end

      def return_jwt_header_error(env)
        if env['HTTP_AUTHORIZATION'].nil?
          return_error('Missing Authorization header')
        elsif env['HTTP_AUTHORIZATION'].split(' ').first != 'Bearer'
          return_error('Invalid Authorization header format')
        end
      end

      def valid_header?(env)
        env['HTTP_AUTHORIZATION'] =~ /\ABearer \S*\.\S*\.\S*\z/
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
