{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.Token
  ( createJwtAccessToken
  , decodeJwtRefreshToken
  )
where

import Prelude hiding (exp)

import Control.Applicative ((<$>), (<*>))
import Control.Monad (liftM)
import Data.Aeson
import Data.Aeson.Types
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Int (Int64)
import Data.Text (Text)
import Data.Time.Clock.POSIX
import GHC.Generics

import qualified Crypto.PubKey.RSA as RSA

import Broch.Model
import Broch.Random
import Jose.Jwa
import Jose.Jwt
import qualified Jose.Jwe as Jwe

tokenTTL :: POSIXTime
tokenTTL = 3600

refreshTokenTTL :: POSIXTime
refreshTokenTTL = 3600 * 24

createJwtAccessToken :: RSA.PublicKey
                     -> Maybe SubjectId
                     -> Client
                     -> GrantType
                     -> [Scope]
                     -> POSIXTime
                     -> IO (ByteString, Maybe ByteString, TokenTTL)
createJwtAccessToken pubKey user client grantType scopes now = do
      token <- toJwt claims
      refreshToken <- issueRefresh
      return (token, refreshToken, tokenTTL)
    where
      toJwt t = withCPRG $ \cprg -> Jwe.rsaEncode cprg RSA_OAEP A128GCM pubKey (toStrict $ encode t)
      issueRefresh
        | grantType /= Implicit && RefreshToken `elem` authorizedGrantTypes client = fmap Just $ toJwt refreshClaims
        | otherwise = return Nothing
      subject = case user of
                  Just s  -> s
                  Nothing -> clientId client
      claims = Claims
                 { iss = "Broch"
                 , sub = subject
                 , grt = grantType
                 , cid = clientId client
                 , aud = ["nobody"]
                 , exp = TokenTime $ now + tokenTTL
                 , nbf = Nothing
                 , iat = TokenTime now
                 , jti = Nothing
                 , scp = (map scopeName scopes)
                 }
      refreshClaims = claims
                        { exp = TokenTime $ now + refreshTokenTTL
                        , aud = ["refresh"]
                        }

decodeJwtRefreshToken :: RSA.PrivateKey -> ByteString -> Maybe AccessGrant
decodeJwtRefreshToken privKey jwt = case claims of
                                        Right (Just c)  -> Just $ claimsToAccessGrant c
                                        _               -> Nothing
                                    where
                                        claims = fmap decodeClaims $ Jwe.rsaDecode privKey jwt

                                        decodeClaims :: (JwtHeader, ByteString) -> Maybe Claims
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


omitNothingOptions :: Options
omitNothingOptions = defaultOptions { omitNothingFields = True }

data Claims = Claims
      { iss :: Text
      , sub :: Text
      , grt :: GrantType
      , cid :: Text
      , aud :: [Text]
      , exp :: TokenTime
      , nbf :: Maybe TokenTime
      , iat :: TokenTime
      , jti :: Maybe Text
      , scp :: [Text]
      } deriving (Generic)

instance ToJSON Claims where
    toJSON = genericToJSON omitNothingOptions

instance FromJSON Claims where
    parseJSON = genericParseJSON omitNothingOptions

