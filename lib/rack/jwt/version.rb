module Rack
  module JWT
    VERSION = '1.0.0'.freeze

    CHANGE_LOG = <<-LOG
      '1.0.0': Update jwt version in gemspec file
      '0.7.0': Added ability to specify http verb per exclude and option paths
      '0.6.1': Clear jwt sub on thread local after request finishes
      '0.6.0': Add jwt sub to a thread local variable, for logging
      '0.5.0': remove logging on missing auth header
      '0.4.0': early forks of rack-jwt added regex exclude paths, optional exclude paths, and
               configurable logger

    LOG
  end
end
