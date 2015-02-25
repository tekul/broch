{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.IdToken
    ( IdToken (..)
    , idTokenClaims
    , idTokenHash
    )
where

import Prelude hiding (exp)

import Crypto.PubKey.HashDescr
import Data.Aeson.Types
import Data.ByteString
import qualified Data.ByteString as B
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX
import GHC.Generics
import Jose.Jwa
import Jose.Jwt
import qualified Jose.Internal.Base64 as B64

import Broch.Model



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
    idTokenTTL = 1000
    idtHash = idTokenHash client

idTokenHash :: Client
            -> ByteString
            -> Text
idTokenHash client token = TE.decodeUtf8 $ B64.encode $ B.take l h
  where
    h = hash token
    l = B.length h `div` 2
    sigAlg = case idTokenAlgs client of
        Just (AlgPrefs (Just s) _) -> s
        _                          -> RS256

    hash = hashFunction $ case sigAlg of
        RS256 -> hashDescrSHA256
        RS384 -> hashDescrSHA384
        RS512 -> hashDescrSHA512
        HS256 -> hashDescrSHA256
        HS384 -> hashDescrSHA384
        HS512 -> hashDescrSHA512
        ES256 -> hashDescrSHA256
        ES384 -> hashDescrSHA384
        ES512 -> hashDescrSHA512
        None  -> error "id_token must be signed"

