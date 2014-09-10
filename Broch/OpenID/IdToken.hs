{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.IdToken where

import Prelude hiding (exp)

import Crypto.PubKey.HashDescr
import Crypto.PubKey.RSA (PrivateKey)
import Crypto.Random (CPRG)
import Data.Aeson
import Data.Aeson.Types
import Data.ByteString
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Time (NominalDiffTime)
import Data.Time.Clock.POSIX
import GHC.Generics
import Jose.Jwa
import Jose.Jws
import Jose.Jwt (IntDate (..), JwtError)
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


-- TODO: Add support for nested JWE token

createIdTokenJws :: CPRG g
                 => g
                 -> JwsAlg                        -- JWS encoding
                 -> PrivateKey
                 -> Text                          -- Issuer
                 -> ClientId                      -- Audience
                 -> Maybe Text                    -- Authorization request nonce
                 -> SubjectId                     -- Subject
                 -> POSIXTime                     -- Current time
                 -> Maybe ByteString
                 -> Maybe ByteString
                 -> (Either JwtError ByteString, g)
createIdTokenJws rng a key issuer clid n subject now code accessToken =
    rsaEncode rng a key $ BL.toStrict . encode $ IdToken
        { iss = issuer
        , sub = subject
        , aud = [clid]
        , exp = IntDate $ now + idTokenTTL
        , iat = IntDate now
        , nonce = n
        , acr = Nothing
        , amr = Nothing
        , azp = Nothing
        , c_hash = fmap idtHash code
        , at_hash = fmap idtHash accessToken
        }
  where
    idtHash b = let h = hash b
                    l = B.length h `div` 2
                in TE.decodeUtf8 $ B64.encode $ B.take l h
    hash = hashFunction $ case a of
        RS256 -> hashDescrSHA256
        RS384 -> hashDescrSHA384
        RS512 -> hashDescrSHA512
        HS256 -> hashDescrSHA256
        HS384 -> hashDescrSHA384
        HS512 -> hashDescrSHA512
        None  -> error "id_token must be signed"




