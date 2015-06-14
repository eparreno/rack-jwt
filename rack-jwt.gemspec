# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rack/jwt/version'

Gem::Specification.new do |spec|
  spec.name          = "rack-jwt"
  spec.version       = Rack::Jwt::VERSION
  spec.authors       = ["Mr. Eigenbart"]
  spec.email         = ["eigenbart@gmail.com"]
  spec.summary       = %q{Rack middleware that provides authentication based on JSON Web Tokens.}
  spec.description   = %q{Rack middleware that provides authentication based on JSON Web Tokens.}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]
  spec.required_ruby_version = '>= 1.9.3'

  spec.add_development_dependency 'bundler', '~> 1.7'
  spec.add_development_dependency 'rake', '~> 10.0.0'
  spec.add_development_dependency 'rack-test', '~> 0.6.3'
  spec.add_development_dependency 'rspec',     '~> 3.2.0'

  spec.add_runtime_dependency 'rack', '>= 1.6.0'
  spec.add_runtime_dependency 'jwt', '~> 1.5.0'
end
