{-# LANGUAGE OverloadedStrings, Rank2Types #-}

module Broch.OAuth2.ClientAuth where

import           Control.Applicative
import           Control.Error
import           Control.Monad.Trans (lift)
import           Control.Monad (join, unless)
import           Crypto.Random (CPRG)
import           Data.Aeson hiding (decode)
import           Data.Byteable (constEqBytes)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Base64 as B64
import           Data.Map (Map)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import           Data.Time.Clock.POSIX (POSIXTime)
import           Jose.Jwt
import           Jose.Jws

import qualified Broch.OAuth2.Internal as I
import           Broch.Model

data ClientAuthError = InvalidRequest Text
                     | InvalidClient
                     | InvalidClient401
                       deriving (Show, Eq)

instance ToJSON ClientAuthError where
    toJSON (InvalidRequest m) = object ["error" .= ("invalid_request" :: Text), "error_description" .= m]
    toJSON _                  = object ["error" .= ("invalid_client" :: Text)]


-- | Authenticate the client using one of the methods defined in
-- http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
-- On failure an invalid_client error is returned with a 400 error
-- code, or 401 if the client used the Authorization header.
-- See http://tools.ietf.org/html/rfc6749#section-5.2
authenticateClient :: (Monad m, CPRG g)
                   => Map Text [Text]
                   -> Maybe ByteString
                   -> POSIXTime
                   -> LoadClient m
                   -> WithCPRG m g
                   -> m (Either ClientAuthError Client)
authenticateClient env authzHeader now getClient withRng = runEitherT $ do
    clid      <- maybeParam "client_id"
    secret    <- maybeParam "client_secret"
    assertion <- maybeParam "client_assertion"
    aType     <- maybeParam "client_assertion_type"

    -- TODO: Return auth type here so it can be checked after
    -- authenticating
    client <- case (authzHeader, clid, secret, assertion, aType) of
        (Just h,  _, Nothing, Nothing, Nothing)         -> noteT InvalidClient401 $ basicAuth h
        (Nothing, Just cid, Just sec, Nothing, Nothing) -> noteT InvalidClient    $ checkClientSecret cid sec
        (Nothing, _, Nothing, Just a, Just "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                                                        -> noteT InvalidClient $ clientAssertionAuth a
        (Nothing, _, Nothing, Nothing, Nothing)         -> left InvalidClient
        _                                               -> left $ InvalidRequest "Multiple authentication credentials/mechanisms or malformed authentication data"
    checkClientId clid client

    return client
  where
    clientAssertionAuth a = do
        (hdr, claims)   <- hushT . hoistEither $ decodeClaims $ TE.encodeUtf8 a
        alg <- case hdr of
            JwsH h -> just $ jwsAlg h
            _      -> nothing
        -- TODO: Check audience
        unless (jwtIss claims == jwtSub claims) nothing
        IntDate expiry  <- hoistMaybe $ jwtExp claims
        unless (expiry > now) nothing
        -- TODO: Introduce jti caching
        cid             <- hoistMaybe $ jwtSub claims
        client          <- hoistMaybe =<< lift (getClient cid)
        let authMethod = tokenEndpointAuthMethod client
        let authAlg    = tokenEndpointAuthAlg client
        unless (isNothing authAlg || authAlg == Just alg) nothing
        let jwt        = TE.encodeUtf8 a

        case authMethod of
            ClientSecretJwt -> do
                sec  <- hoistMaybe $ clientSecret client
                either (const nothing) (const $ just client) $ hmacDecode (TE.encodeUtf8 sec) jwt
            PrivateKeyJwt   -> do
                keys           <- hoistMaybe $ clientKeys client
                validOrInvalid <- lift $ withRng $ \g -> decode g keys jwt
                either (const nothing) (const $ just client) validOrInvalid
            _               -> nothing

    basicAuth h    = do
        (cid, secret) <- hoistMaybe decodedHeader
        checkClientSecret cid secret
      where
        decodedHeader = case B.split ' ' h of
            ["Basic", b] -> join $ creds <$> hush (B64.decode b)
            _            -> Nothing

        creds bs = case T.break (== ':') <$> TE.decodeUtf8' bs of
            Right (u, p) -> if T.length p == 0
                                then Nothing
                                else Just (u, T.tail p)
            _            -> Nothing

    checkClientSecret cid secret = do
        -- TODO: Fixed delay based on cid and secret
        client <- lift $ getClient cid
        hoistMaybe $ case client of
            Nothing -> Nothing
            Just c  -> clientSecret c >>= \s ->
                if constEqBytes (TE.encodeUtf8 s) (TE.encodeUtf8 secret)
                    then Just c
                    else Nothing

    checkClientId cid client = case cid of
        Nothing -> return ()
        Just c  -> unless (c == clientId client) $ left $ InvalidRequest "client_id parameter is doesn't match authentication"

    maybeParam name = either (left . InvalidRequest) right $ I.maybeParam env name


