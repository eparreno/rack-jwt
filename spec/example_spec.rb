require 'spec_helper'

describe 'README examples' do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  describe 'work as expected with' do
    let(:time) { Time.new(2014, 02, 06, 16, 12, 0, '-08:00') }

    before do
      allow(Time).to receive_message_chain(:now).and_return(time)
    end

    # behavior of this is changing after jwt v1.5.2 when you can specify a lambda for verify_jti
    # right now its hard-coded to verify against an MD5
    let(:jti_digest) { Digest::MD5.hexdigest([secret, Time.now.to_i].join(':').to_s) }

    let(:payload) do
      {
        data: 'data',
        exp: Time.now.to_i + 4 * 3600,
        nbf: Time.now.to_i - 3600,
        iss: 'https://my.awesome.website/',
        aud: 'audience',
        jti: jti_digest,
        iat: Time.now.to_i,
        sub: 'subject'
      }
    end

    let(:decode_args) do
      {
        secret: secret,
        verify: true,
        options: {
          algorithm: 'HS256',
          verify_expiration: true,
          verify_not_before: true,
          iss: 'https://my.awesome.website/',
          verify_iss: true,
          verify_iat: true,
          jti: jti_digest,
          verify_jti: true,
          aud: 'audience',
          verify_aud: true,
          sub: 'subject',
          verify_sub: true,
          leeway: 30
        }
      }
    end

    let(:app) { Rack::JWT::Auth.new(inner_app, decode_args) }

    it 'valid sample code' do
      header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
      get('/')
      expect(last_response.status).to eq 200
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body).to eq(payload)
      expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"HS256"})
    end
  end
end
