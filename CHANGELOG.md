# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1-mp5] - 2025-07-28

### ️🚀  Features
- Feat : test gitcliff

### 🐛 Bug Fixes
- Git cliff configuration for changelog

[0.6.1-mp5]: https://github.com///compare/v0.6.1-mp4..v0.6.1-mp5

## [0.6.1-mp4] - 2025-07-25

### ⚙️ Miscellaneous Tasks
- Improve ci for changelog
- Change git cliff conf

## [0.6.1-mp3] - 2025-07-25

### ⚙️ Miscellaneous Tasks
- Update README.md

### ️🚀  Features
- Add auto changelog & release
- Add cargo chef & zigbuild to improve performance of docker build
- No need aarch64 support in Dockerfile so revert (it does not work)
- Add multiplatform docker buildx & push

## [0.6.1] - 2025-02-17

### Release
- V0.6.1

### ️🚀  Features
- Documentation for optional prefix
- Optional prefix in path configured via env var

### 🐛 Bug Fixes
- Align log syntax with existing code
- Update rust.yml to be triggered on "develop"

## [0.5.11] - 2023-11-23

### Release
- V0.5.11

### ️🚀  Features
- Feat : add pkcs8 format to get private key from file

## [0.5.10c] - 2023-11-22

## [0.5.10b] - 2023-11-21

### Merge
- MR

### Release
- V0.5.10

### ⚙️ Miscellaneous Tasks
- Update docker-image.yml

### 📚 Documentation
- Update README.md

## [0.5.9] - 2023-06-28

### Release
- V0.5.9

### 🐛 Bug Fixes
- Tests

## [0.5.8] - 2023-06-28

### Release
- V0.5.8 (tests fixed)

## [0.5.7] - 2023-06-28

### Release
- V0.5.7

### ⚙️ Miscellaneous Tasks
- Fix dockerfile to enable musl..

### 🐛 Bug Fixes
- Finally remove openssl in favor of rsa+ssh1
- :construction: still attempting to build image... now require musl compatible

## [0.5.6] - 2023-06-28

### Release
- V0.5.6

### 🐛 Bug Fixes
- Attempt to fix build - openssl issue on windows
- Remove rust-musl-builder in favor on latest rust image...

## [0.5.5] - 2023-06-27

### Release
- V0.5.5

### 🐛 Bug Fixes
- Remove weird cargo update

## [0.5.4] - 2023-06-27

### Release
- V0.5.4

### 🚜 Refactor
- Remove base64 deprecated function

## [0.5.3] - 2023-06-27

### Release
- V0.5.3

## [0.5.2] - 2023-06-27

### Release
- V0.5.2

### 🐛 Bug Fixes
- Remove chrono in favor of time
- :construction: attempt to fix dependency version resolution conflicts

## [0.5.1] - 2023-06-27

### Release
- V0.5.1

### ⚙️ Miscellaneous Tasks
- Bump to 0.5.0

### ️🚀  Features
- Declare route + update usecases
- Add bcrypt/verify
- Add API KEYS support if env var provided
- Add API KEYS support if env var provided

## [0.4.2] - 2022-06-16

### ⚙️ Miscellaneous Tasks
- Use release time
- Rework scripts
- Add wrk launcher
- Chmod +x

### ⚡ Performance
- Parse EncodingKey only once on server startup
- Parse EncodingKey only once on server startup

### ️🚀  Features
- Bump version to 0.4.2

## [0.4.1] - 2022-06-08

### 🐛 Bug Fixes
- Fix: make sure cargo.lock is up to date with 0.4.1 before releasing....

## [0.4.0] - 2022-06-08

### ⚙️ Miscellaneous Tasks
- Ignore intellij files
- Cleanup + move 'local' stuff in 'local/' directory
- Build on develop not only master

### ️🚀  Features
- Bump version to 0.4.0
- Add encrypt/decrypt endpoints
- Add encryp/decrpt endpoints

### 🐛 Bug Fixes
- Link
- Add badge
- Missing unwrap...

### 🚜 Refactor
- /health returns a JSON with application version too

## [0.3.1] - 2022-03-31

### 🐛 Bug Fixes
- Cargo.lock must be bumped manually to prevent permission issue during build

## [0.3.0] - 2022-03-31

### ⚙️ Miscellaneous Tasks
- Add docker badge"
- Fix markdown
- Add CHANGELOG

### ️🚀  Features
- New api => new minor version
- Add latest tag

## [0.2.5] - 2022-03-31

### ⚙️ Miscellaneous Tasks
- Add LOCAL recipe

### ️🚀  Features
- To_public_key utility fn + cargo fmt
- Extract public from private key + add verify route
- Add ctor for tests + openssl to extract public from private key
- Add /health endpoint which should return "OK" with a 200 http status

### 🚜 Refactor
- Cleanup error message + add usecase to ease e2eé

## [0.2.4] - 2021-05-19

### ⚙️ Miscellaneous Tasks
- V0.2.4

## [0.2.3] - 2021-05-19

### ⚙️ Miscellaneous Tasks
- 0.2.3

### ️🚀  Features
- Add 'duration_seconds' query parameters
- Add badges
- Add sample docker-compose

## [0.2.2] - 2021-05-04

### ️🚀  Features
- Bind on 0.0.0.0 by default

## [0.2.1] - 2021-05-04

### ️🚀  Features
- Add docker push

## [0.2.0] - 2021-05-04

### ️🚀  Features
- Bump version + read private key on startup
- Attempt to build tag/latest docker image
- README in md to ease dockerhub integration
- Load private key only once at startup
- Cleanup logs
- Polishing error mngt
- Somewhat a 'better' error handling...

### 🐛 Bug Fixes
- Invalid wip code...
- Name + refs/head*S* ...
- Github.ref NOT GITHUB_REF on expr...
- Version tag regex does not match with head/master
- Yamlery...
- Yamlery...
- Yamlery...

### 🚜 Refactor
- Split errors + remove unwanted code

## [basics] - 2021-05-02

### ️🚀  Features
- Update README
- Rework sign with generic generate behavior
- Keep track of usage
- Auth+sign endpoints
- Warp + jsonwebtoken; wip

[unreleased]: https://github.com/Arnauld/jwtd/compare/v0.6.1-mp4..HEAD
[0.6.1-mp4]: https://github.com/Arnauld/jwtd/compare/v0.6.1-mp3..v0.6.1-mp4
[0.6.1-mp3]: https://github.com/Arnauld/jwtd/compare/v0.6.1..v0.6.1-mp3
[0.6.1]: https://github.com/Arnauld/jwtd/compare/v0.5.11..v0.6.1
[0.5.11]: https://github.com/Arnauld/jwtd/compare/v0.5.10c..v0.5.11
[0.5.10c]: https://github.com/Arnauld/jwtd/compare/v0.5.10b..v0.5.10c
[0.5.10b]: https://github.com/Arnauld/jwtd/compare/v0.5.9..v0.5.10b
[0.5.9]: https://github.com/Arnauld/jwtd/compare/v0.5.8..v0.5.9
[0.5.8]: https://github.com/Arnauld/jwtd/compare/v0.5.7..v0.5.8
[0.5.7]: https://github.com/Arnauld/jwtd/compare/v0.5.6..v0.5.7
[0.5.6]: https://github.com/Arnauld/jwtd/compare/v0.5.5..v0.5.6
[0.5.5]: https://github.com/Arnauld/jwtd/compare/v0.5.4..v0.5.5
[0.5.4]: https://github.com/Arnauld/jwtd/compare/v0.5.3..v0.5.4
[0.5.3]: https://github.com/Arnauld/jwtd/compare/v0.5.2..v0.5.3
[0.5.2]: https://github.com/Arnauld/jwtd/compare/v0.5.1..v0.5.2
[0.5.1]: https://github.com/Arnauld/jwtd/compare/v0.4.2..v0.5.1
[0.4.2]: https://github.com/Arnauld/jwtd/compare/v0.4.1..v0.4.2
[0.4.1]: https://github.com/Arnauld/jwtd/compare/v0.4.0..v0.4.1
[0.4.0]: https://github.com/Arnauld/jwtd/compare/v0.3.1..v0.4.0
[0.3.1]: https://github.com/Arnauld/jwtd/compare/v0.3.0..v0.3.1
[0.3.0]: https://github.com/Arnauld/jwtd/compare/v0.2.5..v0.3.0
[0.2.5]: https://github.com/Arnauld/jwtd/compare/v0.2.4..v0.2.5
[0.2.4]: https://github.com/Arnauld/jwtd/compare/v0.2.3..v0.2.4
[0.2.3]: https://github.com/Arnauld/jwtd/compare/v0.2.2..v0.2.3
[0.2.2]: https://github.com/Arnauld/jwtd/compare/v0.2.1..v0.2.2
[0.2.1]: https://github.com/Arnauld/jwtd/compare/v0.2.0..v0.2.1
[0.2.0]: https://github.com/Arnauld/jwtd/compare/basics..v0.2.0

<!-- generated by git-cliff -->
