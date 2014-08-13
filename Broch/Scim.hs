{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.Scim
    ( Meta(..)
    , Name(..)
    , Address(..)
    , Email(..)
    , ScimUser(..)
    , Phone(..)
    )
where

import Data.Aeson
import Data.Aeson.Types(Options(..), defaultOptions)
import Data.Default.Generics
import Data.Char (toLower, toUpper)
import Data.Text (Text)
import Data.Time.Clock (UTCTime)
import GHC.Generics (Generic)
--import Network.URI (URI)

type ScimId = Text

type MT = Maybe Text

data Meta = Meta
    { created      :: !(Maybe UTCTime)
    , lastModified :: !(Maybe UTCTime)
    , location     :: !MT
    , version      :: !MT
    } deriving (Show, Generic)

instance FromJSON Meta
instance ToJSON Meta where
    toJSON = genericToJSON omitNothingOptions

data Name = Name
    { nameFormatted    :: !MT
    , nameFamilyName   :: !MT
    , nameGivenName    :: !MT
    , nameMiddleName   :: !MT
    , nameHonorificPrefix :: !MT
    , nameHonorificSuffix :: !MT
    } deriving (Show, Generic)

instance FromJSON Name
instance ToJSON Name where
    toJSON = genericToJSON omitNothingOptions

instance Default Name


data Email = Email
    { emailValue   :: !Text
    , emailType    :: !MT
    , emailPrimary :: !(Maybe Bool)
    } deriving (Show, Generic)

instance FromJSON Email where
    parseJSON = genericParseJSON emailOptions
instance ToJSON Email where
    toJSON = genericToJSON emailOptions

instance Default Email


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
    toJSON = genericToJSON imOptions

imOptions :: Options
imOptions = prefixOptions "im"

data ScimUser = ScimUser
    { scimId           :: !(Maybe ScimId)
    , scimUserName     :: !Text
    , scimSchemas      :: !(Maybe [Text])
    , scimMeta         :: !(Maybe Meta)
    , scimName         :: Maybe Name
    , scimDisplayName  :: !MT
    , scimNickName     :: !MT
    , scimProfileUrl   :: !MT
    , scimTitle        :: !MT
    , scimUserType     :: !MT
    , scimPreferredLanguage :: !MT
    , scimLocale       :: !MT
    , scimTimezone     :: !MT
    , scimActive       :: !(Maybe Bool)
    , scimEmails       :: !(Maybe [Email])
    , scimAddresses    :: !(Maybe [Address])
    , scimPhoneNumbers :: !(Maybe [Phone])
    , scimIms          :: !(Maybe [IM])
    , scimPassword     :: !MT
    } deriving (Show, Generic)

instance Default ScimUser

instance FromJSON ScimUser where
    parseJSON = genericParseJSON userOptions

instance ToJSON ScimUser where
    toJSON u = genericToJSON userOptions u { scimPassword = Nothing }

userOptions :: Options
userOptions = prefixOptions "scim"

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
