# Rack::JWT

[![Gem Version](https://badge.fury.io/rb/rack-jwt.svg)](http://badge.fury.io/rb/rack-jwt)
[![Build Status](https://travis-ci.org/eigenbart/rack-jwt.svg)](https://travis-ci.org/eigenbart/rack-jwt)
[![Code Climate](https://codeclimate.com/github/eigenbart/rack-jwt/badges/gpa.svg)](https://codeclimate.com/github/eigenbart/rack-jwt)

## DISCLAIMER

This gem is no longer being maintained. If you wanna keep developing this gem get in touch with me `eigenbart@gmail.com`

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

`Rack::JWT::Auth` accepts several configuration options:

* `secret` : required : String || OpenSSL::PKey::RSA || OpenSSL::PKey::EC : A cryptographically secure String (for HMAC algorithms) or a public key object of an appropriate type. Pass in `nil` if you are using the `'none'` algorithm.
* `verify` : optional : Boolean : Determines whether JWT will verify tokens when decoded. Default is `true`. Pass in `false` if you are using the `'none'` algorithm.
* `options` : optional : Hash : A hash of options that are passed through to JWT to configure supported claims. See [the ruby-jwt docs](https://github.com/progrium/ruby-jwt#support-for-reserved-claim-names) for the available options. By default only expiration (exp) and Not Before (nbf) claims are verified. Pass in an algorithm choice like `{ algorithm: 'HS256'}`
* `exclude` : optional : Array : An Array of path strings representing paths that should not be checked for JWT tokens. Excludes sub-paths as well (e.g. `/docs` excludes `/docs/some/thing.html`). Each path should start with a `/`.


### Sinatra

```
use Rack::JWT::Auth, secret: 'you_secret_token_goes_here', verify: true, options: {}, exclude: ['/api/docs']
```

### Cuba

```
Cuba.use Rack::JWT::Auth, secret: 'you_secret_token_goes_here', verify: true, options: {}, exclude: ['/api/docs']
```

### Rails

```
Rails.application.config.middleware.use, Rack::JWT::Auth, secret: Rails.application.secrets.secret_key_base, verify: true, options: {}, exclude: ['/api/docs']
```

## Generating tokens
You can generate JSON Web Tokens for your users using the
`Rack::JWT::Token#encode` method which takes `payload`,
`secret`, and `algorithm` params.

The secret will be either a cryptographically strong random string, or the
secret key component of a public/private keypair of an accepted type depending on
the algorithm you choose. You can see examples of using the various key types at
the [ruby-jwt gem repo](https://github.com/jwt/ruby-jwt/blob/master/README.md)

The `algorithm` is an optional String and can be one of the following (default HMAC 'HS256'):

```
['none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']
```

Usage example:

```
payload = { "foo" => "bar" }
secret  = "my-long-random-secret or a Private Key object"
alg     = 'HS256'

Rack::JWT::Token.encode(payload, secret, alg)
```

It is important to note that the middleware must be configured to match your token's secret and algorithm or the signature verification will not work.

## Contributing

1. Fork it ( https://github.com/[my-github-username]/rack-jwt/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
