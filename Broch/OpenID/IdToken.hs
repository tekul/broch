{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.IdToken
    ( IdToken (..)
    , idTokenClaims
    , idTokenHash
    )
where

import Prelude hiding (exp)

import Crypto.Hash
import Data.Aeson.Types
import qualified Data.ByteArray as BA
import Data.ByteString
import qualified Data.ByteString as B
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX
import GHC.Generics
import Jose.Jwa
import Jose.Jwt
import qualified Jose.Internal.Base64 as B64

import Broch.Model hiding (sub)



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
idTokenHash client token = TE.decodeUtf8 $ B64.encode $ B.take l th
  where
    l = B.length th `div` 2
    sigAlg = case idTokenAlgs client of
        Just (AlgPrefs (Just s) _) -> s
        _                          -> RS256

    th = case sigAlg of
        RS256 -> go SHA256 token
        RS384 -> go SHA384 token
        RS512 -> go SHA512 token
        HS256 -> go SHA256 token
        HS384 -> go SHA384 token
        HS512 -> go SHA512 token
        ES256 -> go SHA256 token
        ES384 -> go SHA384 token
        ES512 -> go SHA512 token
        None  -> error "id_token must be signed"

    go h t = BA.convert (hashWith h t)
