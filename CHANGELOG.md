# Changelog

## [0.3.0](https://github.com/use-lock/server/compare/0.2.0...0.3.0) (2026-09-23)


### ⚠ BREAKING CHANGES

* DirectAccessTokenIssuer, DirectAccessTokenResult, DirectAccessTokenEvent, the direct_access pipeline kind and CurrentAccessToken::context() are gone, and oidc_access_tokens no longer has the name and context columns.
* the owner parameter of createAuthorizationCodeGrantClient() is renamed from user to owner and accepts any Eloquent model; owners are stored by their morph class.

### Features

* add a middleware that passes a token with any of the listed scopes ([#5](https://github.com/use-lock/server/issues/5)) ([c46c02d](https://github.com/use-lock/server/commit/c46c02d341a3d058b3c54476a55f6de25f0c6364))
* let consent narrow scopes and fill open templates ([4683fae](https://github.com/use-lock/server/commit/4683fae903f6429e8a65672a9a369cd41488cd20))
* make client creation public ([0e87560](https://github.com/use-lock/server/commit/0e875608e8bd5975c1c523255818f84fdf76022f))
* remove the direct access token issuer ([820ae97](https://github.com/use-lock/server/commit/820ae97bf31fef91fc738da49ad01304e9629d8d))
* support parameterized scopes ([#7](https://github.com/use-lock/server/issues/7)) ([0763d23](https://github.com/use-lock/server/commit/0763d233eec9010ca27160b4e38dccbe70b9bbb2))


### Bug Fixes

* restore a green check on main ([0ebcd52](https://github.com/use-lock/server/commit/0ebcd5271a29985390c58039415493a8ecd6b9f1))

## [0.2.0](https://github.com/use-lock/server/compare/0.1.0...0.2.0) (2026-09-16)


### Features

* accept backed enums and relative resources in the token middleware ([b20c635](https://github.com/use-lock/server/commit/b20c635e98a9d68567fe288f38a5356f35cb9f01))

## 0.1.0 (2026-09-14)


### Features

* initial release ([a2d427c](https://github.com/use-lock/server/commit/a2d427c26a9118c152a3c1afff910961e7674b5c))


### Bug Fixes

* preserve queued logout delivery after session deletion ([d63de66](https://github.com/use-lock/server/commit/d63de665a5d3c32bf719140c502e2112db909108))
* start releases at 0.1.0 ([57ed6c2](https://github.com/use-lock/server/commit/57ed6c2e9887923e10f72fff18e58ccb82feddfa))
