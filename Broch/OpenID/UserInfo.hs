{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.UserInfo
    ( UserInfo
    , scimUserToUserInfo
    )
where

import           Control.Applicative ((<$>))
import           Data.Aeson
import           Data.Aeson.Types
import           Data.Maybe (fromJust)
import           Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import           Data.Text (Text)
import           GHC.Generics (Generic)

import qualified Broch.Model as M
import           Broch.Scim

type MT = Maybe Text

scimUserToUserInfo :: ScimUser -> UserInfo
scimUserToUserInfo scimUser = UserInfo
    { sub         = fromJust $ scimId scimUser
    , name        = nameFormatted =<< sn
    , given_name  = nameGivenName =<< sn
    , family_name = nameFamilyName =<< sn
    , middle_name = nameMiddleName =<< sn
    , nickname    = scimNickName scimUser
    , preferred_username = Nothing -- There isn't a SCIM version of this
    , profile     = scimProfileUrl scimUser
    , picture     = Nothing
    , website     = Nothing
    , email       = em
    , email_verified = maybe Nothing (\_ -> Just False) em
    , gender      = Nothing
    , birthdate   = Nothing
    , zoneinfo    = Nothing
    , locale      = scimLocale scimUser
    , phone_number = ph
    , phone_number_verified = maybe Nothing (\_ -> Just False) ph
    , address     = fmap scimAddressToAddress ad
    , updated_at  = Nothing -- scimMeta scimUser >>= lastModified >>= return . M.TokenTime . utcTimeToPOSIXSeconds
    }

  where
    m  = scimMeta scimUser
    sn = scimName scimUser
    em = (emailValue . head) <$> scimEmails scimUser
    ad = head                <$> scimAddresses scimUser
    ph = (phoneValue . head) <$> scimPhoneNumbers scimUser

    scimAddressToAddress scimAddr = AddressClaims
        { formatted      = addrFormatted scimAddr
        , street_address = addrStreetAddress scimAddr
        , locality       = addrLocality scimAddr
        , region         = addrRegion scimAddr
        , postal_code    = addrPostalCode scimAddr
        , country        = addrCountry scimAddr
        }


data AddressClaims = AddressClaims
    { formatted      :: !MT
    , street_address :: !MT
    , locality       :: !MT
    , region         :: !MT
    , postal_code    :: !MT
    , country        :: !MT
    } deriving (Generic, Show)

data UserInfo = UserInfo
    { sub                :: !M.SubjectId
    , name               :: !MT
    , given_name         :: !MT
    , family_name        :: !MT
    , middle_name        :: !MT
    , nickname           :: !MT
    , preferred_username :: !MT
    , profile            :: !MT
    , picture            :: !MT
    , website            :: !MT
    , email              :: !MT
    , email_verified     :: !(Maybe Bool)
    , gender             :: !MT
    , birthdate          :: !MT
    , zoneinfo           :: !MT
    , locale             :: !MT
    , phone_number       :: !MT
    , phone_number_verified :: !(Maybe Bool)
    , address            :: !(Maybe AddressClaims)
    , updated_at         :: !(Maybe M.TokenTime)
    } deriving (Generic, Show)

instance ToJSON AddressClaims where
    toJSON = genericToJSON omitNothingOptions

instance ToJSON UserInfo where
    toJSON = genericToJSON omitNothingOptions

omitNothingOptions :: Options
omitNothingOptions = defaultOptions { omitNothingFields = True }




