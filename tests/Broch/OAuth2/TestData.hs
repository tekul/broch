{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Broch.OAuth2.TestData where

import Data.Time.Clock.POSIX

import Broch.Model

-- $ date -r 1400000000
-- Tue 13 May 2014 17:53:20 BST
now = fromIntegral (1400000000 :: Int) :: POSIXTime

-- Authorization from user "cat" to app
catAuthorization = Authorization "cat" (clientId appClient) (TokenTime $ now - 20) [] Nothing (Just "http://app")

loadAuthorization "catcode" = return $ Just catAuthorization
loadAuthorization "catoic"  = return $ Just $ catAuthorization {authzScope = [OpenID]}
loadAuthorization "expired" = return $ Just $ catAuthorization {authzAt = TokenTime $ now - 301}
loadAuthorization _         = return Nothing

authenticateResourceOwner username password
    | username == password = return $ Just username
    | otherwise            = return Nothing

appClient   = Client "app" (Just "appsecret") [AuthorizationCode, RefreshToken] ["http://app2", "http://app"] 99 99 appClientScope False
adminClient = Client "admin" (Just "adminsecret") [ClientCredentials, AuthorizationCode] [] 99 99 adminClientScope False
roClient    = Client "ro" (Just "rosecret") [ResourceOwner] [] 99 99 appClientScope False
jsClient    = Client "js" Nothing [Implicit] [] 99 99 jsClientScope False
allClient   = Client "all" (Just "allsecret") [AuthorizationCode, ClientCredentials, Implicit, ResourceOwner] [] 99 99 appClientScope False

appClientScope   = map CustomScope ["scope1", "scope2", "scope3"]
adminClientScope = appClientScope ++ [CustomScope "admin"]
jsClientScope    = map CustomScope ["weakscope"]

getClient "app"   = return $ Just appClient
getClient "admin" = return $ Just adminClient
getClient "js"    = return $ Just jsClient
getClient _       = return Nothing
