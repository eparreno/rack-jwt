require 'spec_helper'

describe Rack::JWT::Auth do
  include Rack::Test::Methods

  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'foo' }
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
      expect{ Rack::JWT::Auth.new(main_app, {}) }.to raise_error
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
      expect(subject['error']).to eq('Invalid JWT token')
    end
  end

  context 'when token signature is invalid and JWT verify option is false' do
    let(:app) do
      main_app = lambda { |env| [200, env, [body.to_json]] }
      Rack::JWT::Auth.new(main_app, { secret: secret, verify: false })
    end
    let(:token) { issuer.encode({ iss: 1 }, 'invalid secret') }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

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

  # Test the pass-through of the options Hash to JWT using Issued At (iat) claim to test..
  ###

  context 'when token is valid and an invalid Issued At (iat) claim is provided JWT should ignore bad iat by default' do
    let(:token) { issuer.encode({ iss: 1, iat: Time.now.to_i + 1000000 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

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

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token')
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

end
