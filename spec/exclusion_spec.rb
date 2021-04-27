require 'spec_helper'

describe Rack::JWT::Auth do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:payload) { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: exclusion) }

  describe 'when handling exclusions' do
    context 'with single exclusion' do
      let(:exclusion) do
        [
          { path: '/static', methods: [:get] },
        ]
      end

      context 'with matching exact path and http method' do
        it 'returns a 200' do
          get('/static')
          expect(last_response.status).to eq 200
        end
      end

      context 'with matching exact path with trailing slash and http method' do
        it 'returns a 200' do
          get('/static/')
          expect(last_response.status).to eq 200
        end
      end

      context 'with matching exact path with sub-path and http method' do
        it 'returns a 200' do
          get('/static/foo/bar')
          expect(last_response.status).to eq 200
        end
      end

      context 'with matching exact path but a different http method' do
        it 'returns a 401' do
          post('/static')
          expect(last_response.status).to eq 401
        end
      end
    end

    context 'with multiple exclusions' do
      let(:exclusion) do
        [
          { path: '/books',  methods: :all },
          { path: '/docs',   methods: [:get] },
          { path: '/static', methods: [:get] },
        ]
      end

      context 'with matching path and specific http method' do
        it 'returns a 200' do
          get('/static/foo/bar')
          expect(last_response.status).to eq 200
        end
      end

      context 'with matching path and all http methods' do
        it 'returns a 200', :aggrgate_failures do
          get('/books/foo')
          expect(last_response.status).to eq 200

          post('/books/foo')
          expect(last_response.status).to eq 200

          patch('/books/foo')
          expect(last_response.status).to eq 200

          delete('/books/foo')
          expect(last_response.status).to eq 200
        end
      end

      context 'with matching path but different http method' do
        it 'returns a 401' do
          patch('/static/foo/bar')
          expect(last_response.status).to eq 401
        end
      end

      context 'with no matching path and no token' do
        it 'returns a 401' do
          get('/somewhere')
          expect(last_response.status).to eq 401
        end
      end
    end
  end
end
