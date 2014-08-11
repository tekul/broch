{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.Hspec (hspec)
import qualified Broch.OAuth2.TokenSpec as TokenSpec
import qualified Broch.OAuth2.AuthorizationSpec as AuthorizationSpec
import qualified OAuth2IntegrationSpec as OAuth2IntegrationSpec
import qualified OICIntegrationSpec as OICIntegrationSpec

main :: IO ()
main = hspec $ do
    TokenSpec.spec
    AuthorizationSpec.spec
    OAuth2IntegrationSpec.spec
    OICIntegrationSpec.spec


