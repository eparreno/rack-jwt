require 'pry'
require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

require_relative 'lib/rack/jwt/version.rb'


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

desc "Create tag #{tag}, push --tags, send pkg/rack-jwt-#{version} to gemfury"
task "wb_release" => ["build",
                      "release:guard_clean",
                      "release:source_control_push"] do
  require 'pry'; binding.pry
  1
end

task default: :spec
