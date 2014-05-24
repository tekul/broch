{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Scim

where

import Data.Aeson
import Data.Aeson.Types(Options(..), defaultOptions)
import Data.Char (toLower, toUpper)
import Data.Text (Text)
import Data.Time.Clock (UTCTime)
import GHC.Generics (Generic)
--import Network.URI (URI)

type ScimId = Text

type MT = Maybe Text

data Meta = Meta
    { created      :: !UTCTime
    , lastModified :: !UTCTime
    , location     :: !Text
    , version      :: !Text
    } deriving (Show, Generic)

instance FromJSON Meta
instance ToJSON Meta where
    toJSON = genericToJSON omitNothingOptions

data Name = Name
    { formatted    :: !MT
    , familyName   :: !MT
    , givenName    :: !MT
    , middleName   :: !MT
    , honorificPrefix :: !MT
    , honorificSuffix :: !MT
    } deriving (Show, Generic)

instance FromJSON Name
instance ToJSON Name where
    toJSON = genericToJSON omitNothingOptions

data Email = Email
    { emailValue   :: !Text
    , emailType    :: !MT
    , emailPrimary :: !(Maybe Bool)
    } deriving (Show, Generic)

instance FromJSON Email where
    parseJSON = genericParseJSON emailOptions
instance ToJSON Email where
    toJSON = genericToJSON $ emailOptions

emailOptions :: Options
emailOptions = prefixOptions "email"

data Address = Address
    { addrFormatted     :: !MT
    , addrStreetAddress :: !MT
    , addrLocality      :: !MT
    , addrRegion        :: !MT
    , addrPostalCode    :: !MT
    , addrCountry       :: !MT
    } deriving (Show, Generic)

instance FromJSON Address where
    parseJSON = genericParseJSON addressOptions
instance ToJSON Address where
    toJSON = genericToJSON addressOptions

addressOptions :: Options
addressOptions = prefixOptions "addr"

data Phone = Phone
    { phoneValue :: !Text
    , phoneType  :: !Text
    } deriving (Show, Generic)

instance FromJSON Phone where
    parseJSON = genericParseJSON phoneOptions
instance ToJSON Phone where
    toJSON = genericToJSON phoneOptions

phoneOptions :: Options
phoneOptions = prefixOptions "phone"

data IM = IM
    { imValue :: !Text
    , imType  :: !Text
    } deriving (Show, Generic)

instance FromJSON IM where
    parseJSON = genericParseJSON imOptions
instance ToJSON IM where
    toJSON = genericToJSON $ imOptions

imOptions :: Options
imOptions = prefixOptions "im"

data User = User
    { id           :: !ScimId
    , schemas      :: !(Maybe [Text])
    , meta         :: !(Maybe Meta)
    , userName     :: !Text
    , name         :: Maybe Name
    , displayName  :: !MT
    , nickName     :: !MT
    , profileUrl   :: !MT
    , title        :: !MT
    , userType     :: !MT
    , preferredLanguage :: !MT
    , locale       :: !MT
    , timezone     :: !MT
    , active       :: !(Maybe Bool)
    , emails       :: !(Maybe [Email])
    , addresses    :: !(Maybe [Address])
    , phoneNumbers :: !(Maybe [Phone])
    , ims          :: !(Maybe [IM])
    } deriving (Show, Generic)

instance FromJSON User
instance ToJSON User where
    toJSON = genericToJSON omitNothingOptions

omitNothingOptions :: Options
omitNothingOptions = defaultOptions { omitNothingFields = True }

prefixOptions :: String -> Options
prefixOptions prefix = omitNothingOptions
    { fieldLabelModifier     = dropPrefix $ length prefix
    , constructorTagModifier = addPrefix prefix
    }
  where
    dropPrefix l s = let remainder = drop l s
                     in  (toLower . head) remainder : tail remainder

    addPrefix p s  = p ++ toUpper (head s) : tail s
