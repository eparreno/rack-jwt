# encoding: UTF-8

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rack/jwt/version'

Gem::Specification.new do |spec|
  spec.name          = 'rack-jwt'
  spec.version       = Rack::JWT::VERSION
  spec.authors       = ['Mr. Eigenbart', 'Emili Parreno']
  spec.email         = ['emili@eparreno.com']
  spec.summary       = 'Rack middleware that provides authentication based on JSON Web Tokens.'
  spec.description   = 'Rack middleware that provides authentication based on JSON Web Tokens.'
  spec.homepage      = 'https://github.com/eparreno/rack-jwt'
  spec.license       = 'MIT'

  spec.files         = Dir.glob('lib/**/*') + %w(LICENSE.txt README.md)
  spec.test_files    = spec.files.grep(%r{^spec/})
  spec.require_paths = ['lib']
  spec.platform      = Gem::Platform::RUBY
  spec.required_ruby_version = '>= 2.1.0'

  spec.add_development_dependency 'bundler',   '~> 1.6'
  spec.add_development_dependency 'rake',      '~> 10.5'
  spec.add_development_dependency 'rack-test', '~> 0.6.3'
  spec.add_development_dependency 'rspec',     '~> 3.4.0'
  spec.add_development_dependency 'simplecov', '~> 0.11.2'

  # without it bundler trying to get last rack version, but it needs ruby >= '2.2.2'
  spec.add_runtime_dependency 'rack', RUBY_VERSION <= '2.2.2' ? '~> 1.6' : '>= 1.6.0'
  spec.add_runtime_dependency 'jwt',  '~> 2.3.0'
end
