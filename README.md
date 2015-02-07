# Rack::JWT

This gem provides JSON Web Token (JWT) based authentication.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rack-jwt'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rack-jwt

## Usage

### sinatra

```
use Rack::JWT::Auth secret: 'you_secret_token_goes_here', exclude: ['/api/docs']
```

### Rails

```
Rails.application.config.middleware.use, Rack::JWT::Auth, secret: Rails.application.secrets.secret_key_base, exclude: ['/api/docs']
```

## Generating tokens
You can generate JSON Wen Tokens for your users using the `Token#encode` method

```
Rack::JWT::Token.encode(payload, secret)
```

## Contributing

1. Fork it ( https://github.com/[my-github-username]/rack-jwt/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
