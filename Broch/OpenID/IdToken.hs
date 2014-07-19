{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.IdToken where

import Prelude hiding (exp)

import Data.Aeson
import Data.Aeson.Types
import Data.ByteString
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import Data.Time (NominalDiffTime)
import Data.Time.Clock.POSIX
import GHC.Generics

import Broch.Model


idTokenTTL :: NominalDiffTime
idTokenTTL = 1000

data IdToken = IdToken
    { iss :: Text
    , sub :: SubjectId
    , aud :: [Text]
    , exp :: TokenTime
    , iat :: TokenTime
    , nonce :: Maybe Text
    , acr :: Maybe Text
    , amr :: Maybe [Text]
    , azp :: Maybe Text
    } deriving (Show, Generic)

omitNothingOptions :: Options
omitNothingOptions = defaultOptions { omitNothingFields = True }


instance ToJSON IdToken where
    toJSON = genericToJSON omitNothingOptions

instance FromJSON IdToken where
    parseJSON = genericParseJSON omitNothingOptions


-- TODO: Add support for nested JWE token

createIdTokenJws :: (ByteString -> ByteString)    -- JWS encoding
                 -> Text                          -- Issuer
                 -> ClientId                      -- Audience
                 -> Maybe Text                    -- Authorization request nonce
                 -> SubjectId                     -- Subject
                 -> POSIXTime                     -- Current time
                 -> ByteString
createIdTokenJws jwsEncode issuer clid nonce subject now =
    jwsEncode . BL.toStrict . encode $ IdToken
        { iss = issuer
        , sub = subject
        , aud = [clid]
        , exp = TokenTime $ now + idTokenTTL
        , iat = TokenTime now
        , nonce = nonce
        , acr = Nothing
        , amr = Nothing
        , azp = Nothing
        }

