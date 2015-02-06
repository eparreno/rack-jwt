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
        if @exclude.include? env["PATH_INFO"]
          @app.call(env)
        elsif env["HTTP_AUTHORIZATION"]
          begin
            if env["HTTP_AUTHORIZATION"].split(" ").first != 'Bearer'
              invalid_auth_header
            else
              token = env["HTTP_AUTHORIZATION"].split(" ")[-1]
              decoded_token = Token.decode(token, @secret)
              env["jwt.header"]  = decoded_token.last
              env["jwt.payload"] = decoded_token.first
              @app.call(env)
            end
          rescue
            unauthorized
          end
        else
          no_auth_header
        end
      end

      private

      def unauthorized
        body = { error: "Invalid JWT token" }.to_json
        headers = {
                    'Content-Type' => 'application/json',
                    'Content-Length' => body.bytesize.to_s
                  }

        return [401, headers, [body]]
      end

      def no_auth_header
        body = { error: "Missing Authorization header" }.to_json
        headers = {
                    'Content-Type' => 'application/json',
                    'Content-Length' => body.bytesize.to_s
                  }

        return [401, headers, [body]]
      end

      def invalid_auth_header
        body = { error: "Invalid Authorization header format" }.to_json
        headers = {
                    'Content-Type' => 'application/json',
                    'Content-Length' => body.bytesize.to_s
                  }

        return [401, headers, [body]]
      end
    end
  end
end
