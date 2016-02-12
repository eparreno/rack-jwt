require 'spec_helper'

describe Rack::JWT::Auth do
  include Rack::Test::Methods

  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:options) { {} }
  let(:body)    {{ 'foo' => 'bar' }}

  let(:app) do
    main_app = lambda { |env| [200, env, [body.to_json]] }
    Rack::JWT::Auth.new(main_app, { secret: secret })
  end

  def perform_request
    get('/', {}, headers)
  end

  context 'when no secret provided' do
    let(:headers) { {} }

    it 'raises an exception' do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      expect{ Rack::JWT::Auth.new(main_app, {}) }.to raise_error(KeyError)
    end
  end

  context 'when no authorization header provided' do
    let(:headers) { {} }

    subject { JSON.parse(last_response.body) }

    before { perform_request }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Missing Authorization header')
    end
  end

  context 'when authorization header does not contain the schema' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => token }}

    subject { JSON.parse(last_response.body) }

    before { perform_request }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid Authorization header format')
    end
  end

  context 'when authorization header contains an invalid schema' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "WrongScheme #{token}" }}

    subject { JSON.parse(last_response.body) }

    before { perform_request }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid Authorization header format')
    end
  end

  context 'when token signature is invalid' do
    let(:token) { issuer.encode({ iss: 1 }, 'invalid secret') }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    subject { JSON.parse(last_response.body) }

    before { perform_request }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Signature Verification Error')
    end
  end

  context 'when token signature is invalid and JWT verify option is false' do
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, verify: false })
    end
    let(:token) { issuer.encode({ iss: 1 }, 'invalid secret') }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end
  end

  context 'when token is valid' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    subject { JSON.parse(last_response.body) }

    before { perform_request }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end

    it 'process the request' do
      expect(subject).to eq(body)
    end

    it 'adds the token payload to the request' do
      payload = last_response.header['jwt.payload']
      expect(payload['iss']).to eq(1)
    end

    it 'adds the token header to the request' do
      header = last_response.header['jwt.header']
      expect(header['alg']).to eq('HS256')
      expect(header['typ']).to eq('JWT')
    end
  end

  context 'when HS256 token is valid and issued by jwt.io (test vector)' do
    # token was created with hard-coded secret of 'secret' on the http://jwt.io website
    let(:token) { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    subject { JSON.parse(last_response.body) }

    before { perform_request }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end

    it 'process the request' do
      expect(subject).to eq(body)
    end

    it 'adds the token payload to the request' do
      payload = last_response.header['jwt.payload']
      expect(payload['sub']).to eq("1234567890")
      expect(payload['name']).to eq("John Doe")
      expect(payload['admin']).to eq(true)
    end

    it 'adds the token header to the request' do
      header = last_response.header['jwt.header']
      expect(header['alg']).to eq('HS256')
      expect(header['typ']).to eq('JWT')
    end
  end

  context 'when token is valid but app raises an error unrelated to JWT' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise 'BOOM!' }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    it 'bubbles up the exception' do
      expect { perform_request }.to raise_error('BOOM!')
    end
  end

  context 'Returns proper error response for JWT::VerificationError' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::VerificationError }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Signature Verification Error')
    end
  end

  context 'Returns proper error response for JWT::ExpiredSignature' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::ExpiredSignature }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Expired Signature (exp)')
    end
  end

  context 'Returns proper error response for JWT::IncorrectAlgorithm' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::IncorrectAlgorithm }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Incorrect Key Algorithm')
    end
  end

  context 'Returns proper error response for JWT::ImmatureSignature' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::ImmatureSignature }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Immature Signature (nbf)')
    end
  end

  context 'Returns proper error response for JWT::InvalidIssuerError' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::InvalidIssuerError }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Invalid Issuer (iss)')
    end
  end

  context 'Returns proper error response for JWT::InvalidIatError' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::InvalidIatError }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Invalid Issued At (iat)')
    end
  end

  context 'Returns proper error response for JWT::InvalidAudError' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::InvalidAudError }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Invalid Audience (aud)')
    end
  end

  context 'Returns proper error response for JWT::InvalidSubError' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::InvalidSubError }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Invalid Subject (sub)')
    end
  end

  context 'Returns proper error response for JWT::InvalidJtiError' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::InvalidJtiError }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Invalid JWT ID (jti)')
    end
  end

  context 'Returns proper error response for JWT::DecodeError' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    let(:app) do
      main_app = lambda { |env| raise ::JWT::DecodeError }
      Rack::JWT::Auth.new(main_app, { secret: secret })
    end

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Decode Error')
    end
  end

  # Test the pass-through of the options Hash to JWT using Issued At (iat) claim to test..
  ###

  context 'when token is valid and an invalid Issued At (iat) claim is provided JWT should ignore bad iat by default' do
    let(:token) { issuer.encode({ iss: 1, iat: Time.now.to_i + 1000000 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end

    it 'process the request' do
      expect(subject).to eq(body)
    end

    it 'adds the token payload to the request' do
      payload = last_response.header['jwt.payload']
      expect(payload['iss']).to eq(1)
    end

    it 'adds the token header to the request' do
      header = last_response.header['jwt.header']
      expect(header['alg']).to eq('HS256')
      expect(header['typ']).to eq('JWT')
    end
  end

  context 'when token is valid and an invalid Issued At (iat) claim is provided and iat verification option is enabled' do
    # The token was issued at an insane time in the future.
    let(:iat) { Time.now.to_i + 1000000 }
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, options: { :verify_iat => true } })
    end
    let(:token) { issuer.encode({ iss: 1, iat: iat }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token : Invalid Issued At (iat)')
    end
  end

  context 'when token is valid and a valid Issued At (iat) claim is provided and iat verification option is enabled' do
    # The token was issued at a sane Time.now
    let(:iat) { Time.now.to_i }
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, options: { :verify_iat => true } })
    end
    let(:token) { issuer.encode({ iss: 1, iat: iat }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    before { perform_request }

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end

    it 'process the request' do
      expect(subject).to eq(body)
    end

    it 'adds the token payload to the request' do
      payload = last_response.header['jwt.payload']
      expect(payload['iss']).to eq(1)
    end

    it 'adds the token header to the request' do
      header = last_response.header['jwt.header']
      expect(header['alg']).to eq('HS256')
      expect(header['typ']).to eq('JWT')
    end
  end

  context 'succeeds when retrieving the exact path of an excluded path and no token' do
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, :exclude => ['/static'] })
    end

    before { get "/static", {}, {} }

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end
  end

  context 'succeeds when retrieving the exact path with trailing slash of an excluded path and no token' do
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, :exclude => ['/static'] })
    end

    before { get "/static/", {}, {} }

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end
  end

  context 'succeeds when retrieving the sub-path of an excluded path and no token' do
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, :exclude => ['/static'] })
    end

    before { get "/static/sub/route", {}, {} }

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end
  end

  context 'succeeds when retrieving the sub-path of an excluded path with more than one excluded path and no token' do
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, :exclude => ['/docs', '/books', '/static'] })
    end

    before { get "/static/sub/route", {}, {} }

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end
  end

  context 'fails when retrieving a non-excluded path and no token' do
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, :exclude => ['/docs', '/books', '/static'] })
    end

    before { get "/other/stuff", {}, {} }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end
  end

end
