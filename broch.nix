{ mkDerivation, aeson, aeson-qq, base, blaze-builder, blaze-html
, bytestring, cereal, containers, cookie, cryptonite
, data-default-generics, directory, errors, hspec, http-conduit
, http-types, HUnit, jose-jwt, memory, monad-logger, mtl
, network-uri, optparse-applicative, persistent, persistent-sqlite
, persistent-template, postgresql-simple, reroute, resource-pool
, sqlite-simple, stdenv, text, time, transformers
, unordered-containers, uri-bytestring, uuid, wai, wai-app-static
, wai-extra, warp
}:
mkDerivation {
  pname = "broch";
  version = "0.1";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    aeson base blaze-builder blaze-html bytestring cereal containers
    cookie cryptonite data-default-generics directory errors
    http-conduit http-types jose-jwt memory mtl persistent
    persistent-template postgresql-simple reroute resource-pool
    sqlite-simple text time transformers unordered-containers
    uri-bytestring uuid wai wai-extra
  ];
  executableHaskellDepends = [
    base bytestring cryptonite directory memory monad-logger
    optparse-applicative persistent-sqlite postgresql-simple reroute
    resource-pool sqlite-simple text wai-app-static wai-extra warp
  ];
  testHaskellDepends = [
    aeson aeson-qq base blaze-builder bytestring containers cookie
    cryptonite hspec http-types HUnit jose-jwt memory monad-logger mtl
    network-uri persistent-sqlite text time transformers
    unordered-containers wai wai-extra warp
  ];
  description = "OAuth2/OpenID Connect Server";
  license = stdenv.lib.licenses.bsd3;
}
