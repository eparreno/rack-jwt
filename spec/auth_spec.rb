require 'spec_helper'

describe Rack::JWT::Auth do
  include Rack::Test::Methods

  let(:issuer) { Rack::JWT::Token }
  let(:secret) { 'foo' }

  let(:app) do
    main_app = lambda { |env| [200, env, ['Hello']] }
    Rack::JWT::Auth.new(main_app, {secret: secret})
  end

  it 'raises an exception if no secret provided' do
    expect{ Rack::JWT::Auth.new(main_app, {}) }.to raise_error
  end

  it 'returns 200 ok if the request is authenticated' do
    token = issuer.encode({ iss: 1 }, secret)
    get('/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{token}" })

    expect(last_response.status).to eq 200
    expect(last_response.body).to   eq 'Hello'

    payload = last_response.header['jwt.payload']

    expect(payload['iss']).to  eq(1)
  end

  it 'returns 401 if the authorization header is missing' do
    get('/')

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eq(401)
    expect(jsonResponse['error']).to eq('Missing Authorization header')
  end

  it 'returns 401 if the authorization header signature is invalid' do
    token = issuer.encode({ iss: 1 }, 'invalid secret')
    get('/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{token}" })

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eq(401)
    expect(jsonResponse['error']).to eq('Invalid JWT token')
  end

  it 'returns 401 if the header format is not Authorization: Bearer [token]' do
    token = issuer.encode({ iss: 1 }, secret)
    get('/', {}, { 'HTTP_AUTHORIZATION' => token })

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eq(401)
    expect(jsonResponse['error']).to eq('Invalid Authorization header format')
  end

  it 'returns 401 if authorization scheme is not Bearer' do
    token = issuer.encode({ iss: 1 }, secret)
    get('/', {}, { 'HTTP_AUTHORIZATION' => "WrongScheme #{token}" })

    jsonResponse = JSON.parse(last_response.body)

    expect(last_response.status).to eq(401)
    expect(jsonResponse['error']).to eq('Invalid Authorization header format')
  end
end
