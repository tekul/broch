{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.IdToken where

import Prelude hiding (exp)

import Crypto.PubKey.HashDescr
import Data.Aeson.Types
import Data.ByteString
import qualified Data.ByteString as B
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Time (NominalDiffTime)
import Data.Time.Clock.POSIX
import GHC.Generics
import Jose.Jwa
import Jose.Jwt
import qualified Jose.Internal.Base64 as B64

import Broch.Model


idTokenTTL :: NominalDiffTime
idTokenTTL = 1000

data IdToken = IdToken
    { iss     :: !Text
    , sub     :: !SubjectId
    , aud     :: ![Text]
    , exp     :: !IntDate
    , iat     :: !IntDate
    , auth_time  :: !IntDate
    , nonce   :: !(Maybe Text)
    , acr     :: !(Maybe Text)
    , amr     :: !(Maybe [Text])
    , azp     :: !(Maybe Text)
    , c_hash  :: !(Maybe Text)
    , at_hash :: !(Maybe Text)
    } deriving (Show, Generic)

omitNothingOptions :: Options
omitNothingOptions = defaultOptions { omitNothingFields = True }


instance ToJSON IdToken where
    toJSON = genericToJSON omitNothingOptions

instance FromJSON IdToken where
    parseJSON = genericParseJSON omitNothingOptions


idTokenClaims :: Text                      -- ^ Issuer
              -> Client                    -- ^ Audience
              -> Maybe Text                -- ^ Authorization request nonce
              -> SubjectId                 -- ^ Subject
              -> POSIXTime                 -- ^ Authentication time
              -> POSIXTime                 -- ^ Current time
              -> Maybe ByteString          -- ^ The authorization code
              -> Maybe ByteString          -- ^ The access token
              -> IdToken
idTokenClaims issuer client n subject authenticatedAt now code accessToken = IdToken
        { iss = issuer
        , sub = subject
        , aud = [clientId client]
        , exp = IntDate $ now + idTokenTTL
        , iat = IntDate now
        , auth_time = IntDate authenticatedAt
        , nonce = n
        , acr = Nothing
        , amr = Nothing
        , azp = Nothing
        , c_hash  = fmap idtHash code
        , at_hash = fmap idtHash accessToken
        }
  where
    sigAlg = case idTokenAlgs client of
        Just (AlgPrefs (Just s) _) -> s
        _                          -> RS256
    idtHash b = let h = hash b
                    l = B.length h `div` 2
                in TE.decodeUtf8 $ B64.encode $ B.take l h
    hash = hashFunction $ case sigAlg of
        RS256 -> hashDescrSHA256
        RS384 -> hashDescrSHA384
        RS512 -> hashDescrSHA512
        HS256 -> hashDescrSHA256
        HS384 -> hashDescrSHA384
        HS512 -> hashDescrSHA512
        None  -> error "id_token must be signed"
        _     -> error "EC algorithms are not suported for signing"




