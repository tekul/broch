{-# LANGUAGE OverloadedStrings #-}

module Broch.Class

where

import Crypto.PubKey.RSA (PublicKey, PrivateKey, private_pub)
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.Time.Clock.POSIX (POSIXTime)

import Jose.Jwk

import Broch.Model
import Broch.Token


class OAuth2Server s where
    getClient :: s
              -> Text
              -> IO (Maybe Client)

    createAuthorization :: s
                        -> Text
                        -> OAuth2User
                        -> Client
                        -> POSIXTime
                        -> [Text]
                        -> Maybe Text
                        -> IO ()

    authenticateResourceOwner :: s
                              -> Text
                              -> Text
                              -> IO (Maybe OAuth2User)

    getApproval :: s
                -> Text
                -> Client
                -> POSIXTime
                -> IO (Maybe Approval)

    saveApproval :: s
                -> Approval
                -> IO ()

    getAuthorization :: s
                     -> Text
                     -> IO (Maybe Authorization)

    createAccessToken :: s
                      -> Maybe OAuth2User   -- ^ The end user (resource owner)
                      -> Client             -- ^ The OAuth client the token will be issued to
                      -> GrantType          -- ^ The grant type under which the token was requested
                      -> [Text]             -- ^ The scope granted to the client
                      -> POSIXTime          -- ^ Current time
                      -> IO (ByteString, Maybe ByteString, TokenTTL)
    createAccessToken app = createJwtAccessToken (getPublicKey app)

    decodeRefreshToken :: s
                       -> Client
                       -> Text          -- ^ Refresh token parameter
                       -> IO (Maybe AccessGrant)
    decodeRefreshToken app _ jwt =
        return $ decodeJwtRefreshToken (getPrivateKey app) (encodeUtf8 jwt)

    getPrivateKey :: s
                  -> PrivateKey

    getPublicKey  :: s
                  -> PublicKey
    getPublicKey s = private_pub (getPrivateKey s)

class OAuth2Server s => OpenIDConnectServer s where
    keySet :: s -> JwkSet
    keySet s = JwkSet [RsaPublicJwk (getPublicKey s) (Just "brochkey") Nothing Nothing]

