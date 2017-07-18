require 'spec_helper'

describe Rack::JWT::Auth do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:payload) { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret) }

  describe 'passing throught a claim of type' do
    # TODO : Add another block like this 'iat' block for each of the other claim types?

    describe 'iat' do
      describe 'will succeed' do
        describe 'with a valid iat and verify_iat unset' do
          let(:payload) { { data: 'foo', iat: Time.now.to_i } }
          let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify) }

          it 'will succeed' do
            header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
            get('/')
            expect(last_response.status).to eq 200
            body = JSON.parse(last_response.body, symbolize_names: true)
            expect(body).to eq(payload)
          end
        end

        describe 'with an invalid iat and verify_iat unset' do
          let(:payload) { { data: 'foo', iat: Time.now.to_i + 1_000_000 } }
          let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify) }

          it 'will succeed' do
            header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
            get('/')
            expect(last_response.status).to eq 200
            body = JSON.parse(last_response.body, symbolize_names: true)
            expect(body).to eq(payload)
          end
        end

        describe 'with a valid iat and verify_iat: false' do
          let(:payload) { { data: 'foo', iat: Time.now.to_i } }
          let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify, options: { verify_iat: false }) }

          it 'will succeed' do
            header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
            get('/')
            expect(last_response.status).to eq 200
            body = JSON.parse(last_response.body, symbolize_names: true)
            expect(body).to eq(payload)
          end
        end

        describe 'with a valid iat and verify_iat: true' do
          let(:payload) { { data: 'foo', iat: Time.now.to_i } }
          let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify, options: { verify_iat: true }) }

          it 'will succeed' do
            header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
            get('/')
            expect(last_response.status).to eq 200
            body = JSON.parse(last_response.body, symbolize_names: true)
            expect(body).to eq(payload)
          end
        end
      end

      describe 'will fail' do
        describe 'with an invalid iat and verify_iat true' do
          let(:payload) { { data: 'foo', iat: Time.now.to_i + 1_000_000 } }
          let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify, options: { verify_iat: true }) }

          it 'will succeed' do
            header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
            get('/')
            expect(last_response.status).to eq 401
            body = JSON.parse(last_response.body, symbolize_names: true)
            expect(body).to eq({:error=>"Invalid JWT token : Invalid Issued At (iat)", status: 401})
          end
        end
      end
    end # iat

  end
end
