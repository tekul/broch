{-# LANGUAGE OverloadedStrings #-}

module Broch.Yesod.Class

where

import Control.Monad.IO.Class (liftIO)
import Crypto.PubKey.RSA (PublicKey, PrivateKey, private_pub)
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.Time.Clock.POSIX (POSIXTime)
import Jose.Jwk
import Yesod.Core (Route)
import Yesod.Core.Handler (HandlerT)

import Broch.Model
import Broch.Token


class OAuth2Server site where
    approvalRoute :: site -> Route site

    getClient :: Text
              -> HandlerT site IO (Maybe Client)

    createAuthorization :: Text
                        -> OAuth2User
                        -> Client
                        -> POSIXTime
                        -> [Scope]
                        -> Maybe Text
                        -> HandlerT site IO ()

    authenticateResourceOwner :: Text
                              -> Text
                              -> HandlerT site IO (Maybe OAuth2User)

    getApproval :: Text
                -> Client
                -> POSIXTime
                -> HandlerT site IO (Maybe Approval)

    saveApproval :: Approval
                 -> HandlerT site IO ()

    getAuthorization :: Text
                     -> HandlerT site IO (Maybe Authorization)

    createAccessToken :: Maybe OAuth2User   -- ^ The end user (resource owner)
                      -> Client             -- ^ The OAuth client the token will be issued to
                      -> GrantType          -- ^ The grant type under which the token was requested
                      -> [Scope]            -- ^ The scope granted to the client
                      -> POSIXTime          -- ^ Current time
                      -> HandlerT site IO (ByteString, Maybe ByteString, TokenTTL)
    createAccessToken u c gt s t = do
        k <- getPublicKey
        token <- liftIO $ createJwtAccessToken k u c gt s t
        return token

    decodeRefreshToken :: Client
                       -> Text          -- ^ Refresh token parameter
                       -> HandlerT site IO (Maybe AccessGrant)
    decodeRefreshToken _ jwt =
        getPrivateKey >>= \k -> return $ decodeJwtRefreshToken k (encodeUtf8 jwt)

    getPrivateKey :: HandlerT site IO PrivateKey

    getPublicKey :: HandlerT site IO PublicKey
    getPublicKey = fmap private_pub getPrivateKey

class OAuth2Server site => OpenIDConnectServer site where
    keySet :: HandlerT site IO JwkSet
    keySet = getPublicKey >>= \k -> return $ JwkSet [RsaPublicJwk k (Just "brochkey") Nothing Nothing]

