{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.UserInfo
    ( UserInfo
    , scimUserToUserInfo
    , scopedClaims
    )
where

import           Control.Applicative ((<$>))
import           Data.Aeson
import           Data.Aeson.Types
import           Data.Default.Generics
import           Data.List (foldl')
import           Data.Maybe (fromJust)
--import           Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import           Data.Text (Text)
import           GHC.Generics (Generic)
import           Jose.Jwt (IntDate(..))

import qualified Broch.Model as M
import           Broch.Scim

type MT = Maybe Text

-- | Filter UserInfo data based on the OpenID claims scopes requested.
-- See <<http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims>>
-- for more information.
--
scopedClaims :: [M.Scope]  -- ^ The scope present in the access token
             -> UserInfo   -- ^ The fully populated user info data
             -> UserInfo   -- ^ The (possibly) reduced data
scopedClaims scopes user
    | null oicClaims = emailClaims baseClaims -- No specific scope requested
    | otherwise      = foldl' (\u f -> f u) baseClaims oicClaims
  where
    baseClaims = def { sub = sub user }
    oicClaims = foldl' claimsForScope [] scopes

    claimsForScope acc s = case s of
        M.Profile -> profileClaims : acc
        M.Email   -> emailClaims : acc
        M.Phone   -> phoneClaims : acc
        M.Address -> addressClaims : acc
        _         -> acc

    profileClaims u = u
        { name        = name user
        , given_name  = given_name user
        , family_name = family_name user
        , middle_name = middle_name user
        , nickname    = nickname user
        , preferred_username = preferred_username user
        , profile     = profile user
        , picture     = picture user
        , website     = website user
        }

    emailClaims   u = u { email        = email user, email_verified = email_verified user }
    addressClaims u = u { address      = address user }
    phoneClaims   u = u { phone_number = phone_number user, phone_number_verified = phone_number_verified user }


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
    , updated_at         :: !(Maybe IntDate)
    } deriving (Generic, Show)

instance Default UserInfo

instance ToJSON AddressClaims where
    toJSON = genericToJSON omitNothingOptions

instance ToJSON UserInfo where
    toJSON = genericToJSON omitNothingOptions

omitNothingOptions :: Options
omitNothingOptions = defaultOptions { omitNothingFields = True }




