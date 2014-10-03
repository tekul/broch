{-# LANGUAGE OverloadedStrings, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Broch.OAuth2.TestData where

import Crypto.Random (CPRG(..))
import qualified Data.ByteString as B
import Data.Time.Clock.POSIX
import Jose.Jwt (IntDate(..))

import Broch.Model

-- $ date -r 1400000000
-- Tue 13 May 2014 17:53:20 BST
now = fromIntegral (1400000000 :: Int) :: POSIXTime


-- Fake CPRNG for client authentication
data RNG = RNG

instance CPRG RNG where
    cprgGenerate n g        = (B.replicate n 255, g)
    cprgFork                = undefined
    cprgCreate              = undefined
    cprgSetReseedThreshold  = undefined
    cprgGenerateWithEntropy = undefined

withTestRNG :: (Monad m) => WithCPRG m RNG
withTestRNG f = return $ fst $ f RNG

-- Authorization from user "cat" to app
catAuthorization = Authorization "cat" (clientId appClient) (IntDate $ now - 20) [] Nothing (Just "http://app") (now - 60)

loadAuthorization "catcode" = return $ Just catAuthorization
loadAuthorization "catoic"  = return $ Just $ catAuthorization {authzScope = [OpenID]}
loadAuthorization "expired" = return $ Just $ catAuthorization {authzAt = IntDate $ now - 301}
loadAuthorization _         = return Nothing

authenticateResourceOwner username password
    | username == password = return $ Just username
    | otherwise            = return Nothing

appClient   = Client "app" (Just "appsecret") [AuthorizationCode, RefreshToken] ["http://app2", "http://app"] 99 99 appClientScope False ClientSecretBasic Nothing Nothing Nothing
adminClient = Client "admin" (Just "adminsecret") [ClientCredentials, AuthorizationCode] [] 99 99 adminClientScope False ClientSecretBasic Nothing Nothing Nothing
roClient    = Client "ro" (Just "rosecret") [ResourceOwner] [] 99 99 appClientScope False ClientSecretBasic Nothing Nothing Nothing
jsClient    = Client "js" Nothing [Implicit] [] 99 99 jsClientScope False ClientAuthNone Nothing Nothing Nothing
allClient   = Client "all" (Just "allsecret") [AuthorizationCode, ClientCredentials, Implicit, ResourceOwner] [] 99 99 appClientScope False ClientSecretBasic Nothing Nothing Nothing

appClientScope   = map CustomScope ["scope1", "scope2", "scope3"]
adminClientScope = appClientScope ++ [CustomScope "admin"]
jsClientScope    = map CustomScope ["weakscope"]

getClient "app"   = return $ Just appClient
getClient "admin" = return $ Just adminClient
getClient "js"    = return $ Just jsClient
getClient _       = return Nothing
