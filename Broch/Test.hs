{-# LANGUAGE OverloadedStrings #-}

module Broch.Test where

import           Data.Text (Text)
import           Data.Text.Encoding (encodeUtf8)
import qualified Web.Routing.Combinators as R
import qualified Web.Routing.SafeRouting as R

import           Broch.Model
import           Broch.Server (brochServer, defaultLoginPage,  defaultApprovalPage, authenticatedSubject, authenticateSubject, passwordLoginHandler)
import           Broch.Server.Internal
import           Broch.Server.Config
import           Broch.Test.Data (testClients)


testBroch :: Text -> IO (R.PathMap (Handler ()))
testBroch issuer = do
    kr <- defaultKeyRing
    config <- inMemoryConfig issuer kr Nothing
    mapM_ (createClient config) testClients
    rotateKeys kr True
    -- Allow everything for test options
    let passAuth u p = case (u, p) of
           ("cat", "cat") -> return (Just "1234_cat_id")
           _ -> return Nothing

        loadUserInfo :: LoadUserInfo IO
        loadUserInfo "1234_cat_id" _ = return (Just catUser)
        loadUserInfo sid _ = print sid >> return Nothing

        testConfig = config { responseTypesSupported = map snd responseTypes, getUserInfo = loadUserInfo }

        authenticate username password = passAuth username (encodeUtf8 password)
        extraRoutes =
            [ ("/home",   text "Hello, I'm the home page")
            , ("/login",  passwordLoginHandler defaultLoginPage authenticate)
            , ("/logout", invalidateSession >> complete)
            ]
        routingTable = foldl (\pathMap (r, h) -> R.insertPathMap' (R.toInternalPath (R.static r)) (const h) pathMap) (brochServer testConfig defaultApprovalPage authenticatedSubject authenticateSubject) extraRoutes
    u <- loadUserInfo  "1234_cat_id" (head testClients) :: IO (Maybe UserInfo)
    print u
    return routingTable

catUser :: UserInfo
catUser = UserInfo {
    sub = "1234_cat_id"
  , name = Just "Catherine De Feline"
  , given_name = Just "Catherine"
  , family_name = Just "De Feline"
  , middle_name = Just "Kitty"
  , nickname = Just "Cat"
  , preferred_username = Just "cat"
  , profile = Just "http://placeholder"
  , picture = Just "http://placeholder"
  , website = Just "http://placeholder"
  , email = Just "cat@connect.broch.io"
  , email_verified = Just False
  , gender = Just "female"
  , birthdate = Just "1985-7-23"
  , zoneinfo = Just "Europe/Paris"
  , locale = Just "fr-FR"
  , phone_number = Just "+33 12 34 56 78"
  , phone_number_verified = Just False
  , address = Nothing
  , updated_at = Nothing
  }
