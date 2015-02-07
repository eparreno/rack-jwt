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
              return_error("Invalid Authorization header format")
            else
              token = env["HTTP_AUTHORIZATION"].split(" ")[-1]
              decoded_token = Token.decode(token, @secret)
              env["jwt.header"]  = decoded_token.last
              env["jwt.payload"] = decoded_token.first
              @app.call(env)
            end
          rescue
            return_error("Invalid JWT token")
          end
        else
          return_error("Missing Authorization header")
        end
      end

      private

      def return_error(message)
        body = { error: message }.to_json
        headers = {
                    'Content-Type' => 'application/json',
                    'Content-Length' => message.bytesize.to_s
                  }

        return [401, headers, [body]]
      end
    end
  end
end
