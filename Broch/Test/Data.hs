{-# LANGUAGE OverloadedStrings #-}

module Broch.Test.Data
  ( testClients
  , testUsers
  )
where

import qualified Data.Default.Generics as DD

import           Broch.Model
import           Broch.Scim
import           Broch.URI

testClients :: [Client]
testClients =
    [ DD.def { clientId = "admin", clientSecret = Just "adminsecret", authorizedGrantTypes = [ClientCredentials, AuthorizationCode], redirectURIs = [r "http://admin"], tokenEndpointAuthMethod = ClientSecretBasic }
    , DD.def { clientId = "cf", authorizedGrantTypes = [ResourceOwner], redirectURIs = [r "http://cf.client"], tokenEndpointAuthMethod = ClientAuthNone }
    , DD.def { clientId = "app", clientSecret = Just "appsecret", authorizedGrantTypes = [AuthorizationCode, Implicit, RefreshToken], redirectURIs = [r "http://localhost:8080/app"], tokenEndpointAuthMethod = ClientSecretBasic, allowedScope = [OpenID, CustomScope "scope1", CustomScope "scope2"] }
    ]
  where
    r u = let Right uri = parseURI u in uri

testUsers :: [ScimUser]
testUsers =
    [ DD.def
        { scimUserName = "cat"
        , scimPassword = Just "cat"
        , scimName     = Just $ DD.def {nameFormatted = Just "Tom Cat", nameFamilyName = Just "Cat", nameGivenName = Just "Tom"}
        , scimEmails = Just [DD.def {emailValue = "cat@example.com"}]
        }
    , DD.def { scimUserName = "dog", scimPassword = Just "dog" }
    ]
