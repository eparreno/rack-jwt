require 'pry'
require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

require_relative 'lib/rack/jwt/version.rb'

VERSION = Rack::JWT::VERSION
TAG = "v#{VERSION}"
NAME = Bundler::GemHelper.instance.gemspec.name
PUSH_URL = "https://#{ENV['GEM_SECRET']}@push.fury.io/waybetter/"
PKG_FN = "pkg/#{NAME}-#{VERSION}.gem"

desc 'Run RSpec'
RSpec::Core::RakeTask.new do |t|
  t.verbose = true
end

version=Rack::JWT::VERSION
tag="v#{version}"

#desc "Create tag #{version_tag} and build and push #{name}-#{version}.gem to Rubygems\n" \
#           "To prevent publishing in Rubygems use `gem_push=no rake release`"
#                              "release:guard_clean",
#                              "release:source_control_push",
#                              "release:gemfury_push"] do
#end
Rake::Task["release"].clear # dangerous, slip
desc "[Default rake release disabled, see wb_release]"
task :release do
  puts "Did you mean 'wb-release'? Please see rake -T."
end

<<<<<<< HEAD
task "check_gemfury_repo_access" do
  unless ENV['GEM_SECRET']
    warn "It doesn't look like you have WB_GEM_SOURCE set. Cannot continue."
    exit(1)
  end
end

desc "Create tag #{TAG}, push --tags, send pkg/#{NAME}-#{VERSION} to gemfury.\nYou must set WB_GEM_SOURCE=<our private repo>"
task "wb_release" => ["check_gemfury_repo_access",
                      "build",
                      "release:guard_clean",
                      "release:source_control_push"] do
  if File.exist?(fn = File.expand_path(PKG_FN, '.'))
    cmd = "curl -F package=@#{PKG_FN} #{PUSH_URL}"
    puts cmd
    `#{cmd}`
    if $?.exitstatus.eql?(0)
      puts "\n\n#{fn} now up on gemfury."
    else
      warn "\n\nUpload of #{fn} FAILED"
    end
  else
    warn "Didn't find #{fn}, cannot push it"
    exit(1)
  end

desc "Create tag #{tag}, push --tags, send pkg/rack-jwt-#{version} to gemfury"
task "wb_release" => ["build",
                      "release:guard_clean",
                      "release:source_control_push"] do
  require 'pry'; binding.pry
  1
end

task default: :spec
