{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.Token
  ( createJwtToken
  , createJwtAccessToken
  , decodeJwtAccessToken
  , decodeJwtRefreshToken
  )
where

import Prelude hiding (exp)

import Control.Applicative ((<$>))
import Control.Error
import Control.Monad.State.Strict
import Crypto.Random (CPRG)
import Data.Aeson
import Data.Aeson.Types
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Text (Text)
import Data.Time.Clock.POSIX
import GHC.Generics

import qualified Crypto.PubKey.RSA as RSA

import Broch.Model hiding (sub)
import Broch.Random
import Jose.Jwa
import Jose.Jwk
import qualified Jose.Jwt as Jwt
import qualified Jose.Jwe as Jwe

tokenTTL :: POSIXTime
tokenTTL = 3600

refreshTokenTTL :: POSIXTime
refreshTokenTTL = 3600 * 24

createJwtToken :: (CPRG g, ToJSON a)
               => g
               -> [Jwk]
               -> [Jwk]
               -> AlgPrefs
               -> a
               -> (Either Jwt.JwtError Jwt.Jwt, g)
createJwtToken rng sigKeys encKeys prefs claims = case prefs of
    AlgPrefs s e -> flip runState rng $ runEitherT $ do
        let payload = Jwt.Claims cBytes
        signed <- case s of
            Nothing -> return payload
            Just a  -> fmap Jwt.Nested (hoistEither =<< state (\g -> Jwt.encode g sigKeys (Signed a) Nothing payload))
        case e of
            NotEncrypted -> case signed of
                Jwt.Nested jwt -> return jwt
                Jwt.Claims _   -> left $ Jwt.BadAlgorithm "Can't create a JWT without signature or encryption algorithms"
            E alg enc    -> hoistEither =<< state (\g -> Jwt.encode g encKeys (Encrypted alg) (Just enc) signed)
  where
    cBytes = toStrict (encode claims)

createJwtAccessToken :: (MonadIO m)
                     => RSA.PublicKey
                     -> Maybe SubjectId
                     -> Client
                     -> GrantType
                     -> [Scope]
                     -> POSIXTime
                     -> m (ByteString, Maybe ByteString, TokenTTL)
createJwtAccessToken pubKey user client grantType scopes now = do
      Jwt.Jwt token  <- liftIO $ toJwt claims
      refreshToken   <- liftIO issueRefresh
      return (token, refreshToken, tokenTTL)
    where
      toJwt t = withCPRG $ \cprg -> Jwe.rsaEncode cprg RSA_OAEP A128GCM pubKey (toStrict $ encode t)
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

decodeJwtRefreshToken :: MonadIO m
                      => RSA.PrivateKey
                      -> ByteString
                      -> m (Maybe AccessGrant)
decodeJwtRefreshToken = decodeJwtToken

decodeJwtAccessToken :: MonadIO m
                     => RSA.PrivateKey
                     -> ByteString
                     -> m (Maybe AccessGrant)
decodeJwtAccessToken = decodeJwtToken

decodeJwtToken :: MonadIO m
               => RSA.PrivateKey
               -> ByteString
               -> m (Maybe AccessGrant)
decodeJwtToken privKey jwt = do
    claims <- liftIO $ withCPRG $ \g -> Jwe.rsaDecode g privKey jwt
    return $ case fmap decodeClaims claims of
        Right (Just c)  -> Just $ claimsToAccessGrant c
        _               -> Nothing
  where
    decodeClaims (_, t) = decode $ fromStrict t


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
