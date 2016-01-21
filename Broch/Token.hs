{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.Token
    ( createJwtToken
    , createJwtAccessToken
    , decodeJwtAccessToken
    )
where

import Prelude hiding (exp)

import Control.Error
import Control.Monad.State.Strict
import Crypto.Random (MonadRandom)
import Data.Aeson
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict)
import Data.Text (Text)
import Data.Time.Clock.POSIX
import GHC.Generics

import Broch.Model hiding (sub)
import Jose.Jwk
import qualified Jose.Jwt as Jwt

tokenTTL :: POSIXTime
tokenTTL = 3600

refreshTokenTTL :: POSIXTime
refreshTokenTTL = 3600 * 24

createJwtToken :: (MonadRandom m, ToJSON a)
    => [Jwk]
    -> [Jwk]
    -> AlgPrefs
    -> a
    -> m (Either Jwt.JwtError Jwt.Jwt)
createJwtToken sigKeys encKeys (AlgPrefs s e) claims = runEitherT $ do
    let payload = Jwt.Claims cBytes
    signed <- case s of
        Nothing -> return payload
        Just a  -> do
            jws <- hoistEither =<< lift (Jwt.encode sigKeys (Jwt.JwsEncoding a) payload)
            return (Jwt.Nested jws)
    case e of
        NotEncrypted -> case signed of
            Jwt.Nested jwt -> return jwt
            Jwt.Claims _   -> left $ Jwt.BadAlgorithm "Can't create a JWT without signature or encryption algorithms"
        E alg enc    -> hoistEither =<< lift (Jwt.encode encKeys (Jwt.JweEncoding alg enc) signed)
  where
    cBytes = toStrict (encode claims)

createJwtAccessToken :: MonadRandom m
    => [Jwk]
    -> [Jwk]
    -> AlgPrefs
    -> Maybe SubjectId
    -> Client
    -> GrantType
    -> [Scope]
    -> POSIXTime
    -> m (Either Jwt.JwtError (ByteString, Maybe ByteString, TokenTTL))
createJwtAccessToken sigKeys encKeys prefs user client grantType scopes now = runEitherT $ do
    Jwt.Jwt token  <- toJwt claims
    refreshToken   <- issueRefresh
    return (token, refreshToken, tokenTTL)
  where
    toJwt payload = hoistEither =<< lift (createJwtToken sigKeys encKeys prefs payload)
    issueRefresh
      | grantType /= Implicit && RefreshToken `elem` authorizedGrantTypes client = Just . Jwt.unJwt <$> toJwt refreshClaims
      | otherwise = return Nothing
    subject = fromMaybe (clientId client) user
    claims = Claims
        { iss = "Broch"
        , sub = subject
        , grt = grantType
        , cid = clientId client
        , aud = ["nobody"]
        , exp = Jwt.IntDate $ now + tokenTTL
        , nbf = Nothing
        , iat = Jwt.IntDate now
        , jti = Nothing
        , scp = map scopeName scopes
        }
    refreshClaims = claims
        { exp = Jwt.IntDate $ now + refreshTokenTTL
        , aud = ["refresh"]
        }

decodeJwtAccessToken :: MonadRandom m
    => [Jwk]
    -> [Jwk]
    -> AlgPrefs
    -> ByteString
    -> m (Maybe AccessGrant)
decodeJwtAccessToken sigKeys decKeys (AlgPrefs s e) jwt = runMaybeT $ do
    payload1 <- case e of
        E alg enc -> do
            content <- lift $ Jwt.decode decKeys (Just $ Jwt.JweEncoding alg enc) jwt
            case content of
                Right (Jwt.Jwe (_, bytes)) -> just bytes
                _                          -> nothing
        NotEncrypted -> just jwt

    claims <- case s of
        Nothing  -> just payload1
        Just alg -> do
            content <- lift $ Jwt.decode sigKeys (Just $ Jwt.JwsEncoding alg) payload1
            case content of
                Right (Jwt.Jws (_, bytes)) -> just bytes
                _                          -> nothing

    fmap claimsToAccessGrant $ hoistMaybe $ decodeStrict claims

claimsToAccessGrant :: Claims -> AccessGrant
claimsToAccessGrant claims = AccessGrant
    { granterId = subj
    , granteeId = cid claims
    , accessGrantType = grt claims
    , grantScope = map scopeFromName $ scp claims
    , grantExpiry = exp claims
    }
  where
    subj = if sub claims == cid claims
              then Nothing
              else Just $ sub claims

data Claims = Claims
    { iss :: Text
    , sub :: Text
    , grt :: GrantType
    , cid :: Text
    , aud :: [Text]
    , exp :: Jwt.IntDate
    , nbf :: Maybe Jwt.IntDate
    , iat :: Jwt.IntDate
    , jti :: Maybe Text
    , scp :: [Text]
    } deriving (Generic)

instance ToJSON Claims where
    toJSON = genericToJSON omitNothingOptions

instance FromJSON Claims where
    parseJSON = genericParseJSON omitNothingOptions
