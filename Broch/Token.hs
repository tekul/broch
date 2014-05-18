{-# LANGUAGE OverloadedStrings #-}

module Broch.Token
  ( createJwtAccessToken
  , decodeJwtRefreshToken
  )
where

import Prelude hiding (exp)

import Control.Applicative ((<$>), (<*>))
import Control.Monad (liftM)
import Data.Aeson
import Data.Aeson.Types (Pair)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Text (Text)
import Data.Time.Clock.POSIX
import Data.Word (Word64)
import qualified Data.Text.Encoding as TE

import qualified Crypto.PubKey.RSA as RSA

import Broch.Model
import Broch.Random
import Data.Jwt

tokenTTL = 3600
refreshTokenTTL = 3600 * 24

createJwtAccessToken :: RSA.PublicKey -> Maybe OAuth2User -> Client -> GrantType -> [Text] -> POSIXTime -> IO (ByteString, Maybe ByteString, TokenTTL)
createJwtAccessToken pubKey mUser client grantType scopes now = do
      token <- toJwt claims
      refreshToken <- issueRefresh
      return (token, refreshToken, tokenTTL)
    where
      toJwt t = withCPRG $ \cprg -> jweRsaEncode cprg RSA_OAEP A128GCM pubKey (toStrict $ encode t)
      issueRefresh
        | grantType /= Implicit && RefreshToken `elem` authorizedGrantTypes client = fmap Just $ toJwt refreshClaims
        | otherwise = return Nothing
      subject = case mUser of
                  Just s  -> s
                  Nothing -> clientId client
      claims = Claims
                 { iss = "Broch"
                 , sub = subject
                 , grt = grantType
                 , cid = clientId client
                 , aud = ["nobody"]
                 , exp = now + tokenTTL
                 , nbf = Nothing
                 , iat = now
                 , jti = Nothing
                 , scp = scopes
                 }
      refreshClaims = claims
                        { exp = now + refreshTokenTTL
                        , aud = ["refresh"]
                        }

decodeJwtRefreshToken :: RSA.PrivateKey -> ByteString -> Maybe AccessGrant
decodeJwtRefreshToken privKey jwt = case claims of
                                        Right (Just c)  -> Just $ claimsToAccessGrant c
                                        _               -> Nothing
                                    where
                                        claims = fmap decodeClaims $ jweRsaDecode privKey jwt

                                        decodeClaims :: (JwtHeader, ByteString) -> Maybe Claims
                                        decodeClaims (_, t) = decode $ fromStrict t

claimsToAccessGrant claims = AccessGrant
                          { granterId = subj
                          , granteeId = cid claims
                          , accessGrantType = grt claims
                          , grantScope = scp claims
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
      , exp :: POSIXTime
      , nbf :: Maybe POSIXTime
      , iat :: POSIXTime
      , jti :: Maybe Text
      , scp :: [Text]
      }

instance ToJSON Claims where
    toJSON c = object $ stripNulls
                [ "iss" .= iss c
                , "sub" .= sub c
                , "grt" .= grt c
                , "cid" .= cid c
                , "aud" .= aud c
                , "exp" .= posixTimeToInt (exp c)
                , "nbf" .= fmap posixTimeToInt (nbf c)
                , "iat" .= posixTimeToInt (iat c)
                , "jti" .= jti c
                , "scp" .= scp c
                ]

instance FromJSON Claims where
    parseJSON (Object v) = Claims <$>
        v .: "iss"  <*>
        v .: "sub"  <*>
        v .: "grt"  <*>
        v .: "cid"  <*>
        v .: "aud"  <*>
        liftM intToPosixTime (v .: "exp")  <*>
        liftM (fmap intToPosixTime) (v .:? "nbf") <*>
        liftM intToPosixTime (v .: "iat")  <*>
        v .:? "jti" <*>
        v .: "scp"


stripNulls :: [Pair] -> [Pair]
stripNulls = filter (\(_,v) -> v /= Null)

posixTimeToInt :: POSIXTime -> Word64
posixTimeToInt = fromIntegral . round

intToPosixTime :: Word64 -> POSIXTime
intToPosixTime = fromIntegral
