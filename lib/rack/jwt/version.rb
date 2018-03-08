module Rack
  module JWT
    VERSION = '0.5.0'.freeze

    CHANGE_LOG = <<-LOG
      '0.5.0': remove logging on missing auth header
      '0.4.0': early forks of rack-jwt added regex exclude paths, optional exclude paths, and
               configurable logger

    LOG
  end
end
