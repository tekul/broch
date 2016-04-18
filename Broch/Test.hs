{-# LANGUAGE OverloadedStrings #-}

module Broch.Test where

import           Control.Monad.IO.Class
import qualified Crypto.KDF.BCrypt as BCrypt
import           Crypto.Random (getRandomBytes)
import           Data.ByteArray.Encoding
import           Data.ByteString (ByteString)
import qualified Data.Default.Generics as DD
import           Data.Time.Clock
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import           Data.UUID (toString)
import           Data.UUID.V4
import           Database.Persist.Sql (ConnectionPool, runMigrationSilent, runSqlPersistMPool)
import           Web.Routing.TextRouting

import           Broch.Model
import           Broch.Persist (persistBackend)
import qualified Broch.Persist.Internal as BP
import           Broch.Scim
import           Broch.Server (brochServer, defaultLoginPage,  defaultApprovalPage, authenticatedSubject, authenticateSubject, passwordLoginHandler)
import           Broch.Server.Internal
import           Broch.Server.Config
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

testBroch :: Text -> ConnectionPool -> IO (RoutingTree (Handler ()))
testBroch issuer pool = do
    _ <- runSqlPersistMPool (runMigrationSilent BP.migrateAll) pool
    mapM_ (\c -> runSqlPersistMPool (BP.createClient c) pool) testClients
    mapM_ createUser testUsers
    kr <- defaultKeyRing
    rotateKeys kr True
    config <- persistBackend pool <$> inMemoryConfig issuer kr Nothing
    -- Allow everything for test options
    let testConfig = config { responseTypesSupported = map snd responseTypes }
        extraRoutes =
            [ ("/home",   text "Hello, I'm the home page")
            , ("/login",  passwordLoginHandler defaultLoginPage (authenticateResourceOwner config))
            , ("/logout", invalidateSession >> complete)
            ]
        routingTable = foldl (\tree (r, h) -> addToRoutingTree r h tree) (brochServer testConfig defaultApprovalPage authenticatedSubject authenticateSubject) extraRoutes
    return routingTable
  where
    createUser scimData = do
        now <- Just <$> liftIO getCurrentTime
        uid <- (T.pack . toString) <$> liftIO nextRandom
        password <- maybe randomPassword return (scimPassword scimData)
        hashedPassword <- hashPassword password
        let meta = Meta now now Nothing Nothing
        flip runSqlPersistMPool pool $ BP.createUser uid hashedPassword scimData { scimId = Just uid, scimMeta = Just meta }

    randomPassword :: IO Text
    randomPassword = do
        password <- getRandomBytes 12
        return $ (TE.decodeUtf8 . convertToBase Base64) (password :: ByteString)

    hashPassword p = fmap TE.decodeUtf8 (BCrypt.hashPassword 8 (TE.encodeUtf8 p))
