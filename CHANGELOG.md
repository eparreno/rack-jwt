# Change Log

## [0.7.0](https://github.com/eparreno/rack-jwt/tree/v0.7.0) (2021-04-27)
[Full Changelog](https://github.com/eparreno/rack-jwt/compare/v0.6.0...v0.7.0)

* Change the exclude list format to specify http methods
* When a path is in the exclude list, we still process the token if one is supplied 

## [0.6.0](https://github.com/eparreno/rack-jwt/tree/v0.6.0) (2020-09-29)
[Full Changelog](https://github.com/eparreno/rack-jwt/compare/v0.5.0...v0.6.0)

* Add support for the token to be sent in a cookie, with the name of the cookie 
  configurable via the `cookie_name` option. Headers are still available as a 
  fallback if this is enabled and the cookie is not present.

## [0.5.0](https://github.com/eparreno/rack-jwt/tree/v0.5.0) (2019-12-16)
[Full Changelog](https://github.com/eparreno/rack-jwt/compare/v0.4.0...v0.5.0)

* Upgrade ruby-jwt to version 2.1
* Remove support for Ruby < 2.3.8
* Add ED25519 to `SUPPORTED_ALGORITHMS`
* Content-Length is not set by default anymore

## [0.4.0](https://github.com/eparreno/rack-jwt/tree/v0.4.0) (2018-11-14)
[Full Changelog](https://github.com/eparreno/rack-jwt/compare/v0.3.0...v0.4.0)

* Update ruby-jwt to 2.0.0

## [0.3.0](https://github.com/eparreno/rack-jwt/tree/v0.3.0) (2016-02-19)
[Full Changelog](https://github.com/eparreno/rack-jwt/compare/v0.2.0...v0.3.0)

## [0.2.0](https://github.com/eparreno/rack-jwt/tree/v0.2.0) (2015-07-16)
[Full Changelog](https://github.com/eparreno/rack-jwt/compare/v0.1.1...v0.2.0)

## [0.1.1](https://github.com/eparreno/rack-jwt/tree/v0.1.1) (2015-02-07)
[Full Changelog](https://github.com/eparreno/rack-jwt/compare/v0.1.0...v0.1.1)

## [0.1.0](https://github.com/eparreno/rack-jwt/tree/v0.1.0) (2015-02-06)
