{-# LANGUAGE OverloadedStrings, Rank2Types #-}

module Broch.OAuth2.ClientAuth where

import           Control.Error
import           Control.Monad.Trans (lift)
import           Control.Monad (join, unless)
import           Crypto.Random (MonadRandom)
import           Data.Aeson hiding (decode)
import           Data.ByteArray (constEq)
import           Data.ByteArray.Encoding
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
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
                     | InvalidClient Text
                     | InvalidClient401
                       deriving (Show, Eq)

instance ToJSON ClientAuthError where
    toJSON (InvalidRequest m) = object ["error" .= ("invalid_request" :: Text), "error_description" .= m]
    toJSON (InvalidClient m)  = object ["error" .= ("invalid_client" :: Text),  "error_description" .= m]
    toJSON _                  = object ["error" .= ("invalid_client" :: Text)]


-- | Authenticate the client using one of the methods defined in
-- http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
-- On failure an invalid_client error is returned with a 400 error
-- code, or 401 if the client used the Authorization header.
-- See http://tools.ietf.org/html/rfc6749#section-5.2

authenticateClient :: (Applicative m, MonadRandom m)
    => Map Text [Text]
    -> Maybe ByteString
    -> POSIXTime
    -> LoadClient m
    -> m (Either ClientAuthError Client)
authenticateClient env authzHeader now getClient = runEitherT $ do
    clid      <- maybeParam "client_id"
    secret    <- maybeParam "client_secret"
    assertion <- maybeParam "client_assertion"
    aType     <- maybeParam "client_assertion_type"

    -- TODO: Return auth type here so it can be checked after
    -- authenticating
    client <- case (authzHeader, clid, secret, assertion, aType) of
        (Just h,  _, Nothing, Nothing, Nothing)         -> noteT InvalidClient401 $ basicAuth h
        (Nothing, Just cid, Just sec, Nothing, Nothing) -> noteT (InvalidClient "Secret verification failed") $ checkClientSecret cid sec
        (Nothing, _, Nothing, Just a, Just "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                                                        -> fmapLT InvalidClient $ clientAssertionAuth a
        (Nothing, _, Nothing, Nothing, Nothing)         -> left $ InvalidClient "No authentication information supplied"
        _                                               -> left $ InvalidRequest "Multiple authentication credentials/mechanisms or malformed authentication data"
    checkClientId clid client

    return client
  where
    clientAssertionAuth a = do
        let showT = T.pack . show
        (hdr, claims)   <- hoistEither $ fmapL showT $ decodeClaims (TE.encodeUtf8 a)
        alg <- case hdr of
            JwsH h     -> return (jwsAlg h)
            JweH _     -> left "encrypted assertions are not yet supported"
            UnsecuredH -> left "assertion cannot be an unsecured JWT"
        -- TODO: Check audience
        unless (jwtIss claims == jwtSub claims) (left "assertion 'iss' and 'sub' are different")
        IntDate expiry  <- jwtExp claims ?? "'exp' must be provided in assertion"
        unless (expiry > now) (left "assertion has expired")
        -- TODO: Introduce jti caching
        cid             <- jwtSub claims ?? "missing 'sub' claim in assertion"
        mClient         <- lift $ getClient cid
        client          <- mClient ?? "no such client"
        let authMethod = tokenEndpointAuthMethod client
        let authAlg    = tokenEndpointAuthAlg client
        unless (isNothing authAlg || authAlg == Just alg) (left "assertion 'alg' does not match client registered algorithm")
        let jwt        = TE.encodeUtf8 a

        case authMethod of
            ClientSecretJwt -> do
                sec  <- clientSecret client ?? "client does not have a secret"
                either (left . showT) (const $ return client) $ hmacDecode (TE.encodeUtf8 sec) jwt
            PrivateKeyJwt   -> do
                keys           <- clientKeys client ?? "client has no keys"
                validOrInvalid <- lift $ decode keys (Just (JwsEncoding alg)) jwt
                either (left . showT) (const $ return client) validOrInvalid
            _               -> left "client is not registered to use assertion authentication"

    basicAuth h    = do
        (cid, secret) <- hoistMaybe decodedHeader
        checkClientSecret cid secret
      where
        decodedHeader = case B.split ' ' h of
            ["Basic", b] -> join $ creds <$> hush (convertFromBase Base64 b)
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
                if constEq (TE.encodeUtf8 s) (TE.encodeUtf8 secret)
                    then Just c
                    else Nothing

    checkClientId cid client = case cid of
        Nothing -> return ()
        Just c  -> unless (c == clientId client) $ left $ InvalidRequest "client_id parameter doesn't match authentication"

    maybeParam p = either (left . InvalidRequest) right $ I.maybeParam env p
