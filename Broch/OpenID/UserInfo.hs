module Broch.OpenID.UserInfo
    ( UserInfo
    , scimUserToUserInfo
    , scopedClaims
    )
where

import           Data.Default.Generics (def)
import           Data.List (foldl')
import           Data.Maybe (fromJust)
--import           Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)

import           Broch.Model
import qualified Broch.Scim as Scim


-- | Filter UserInfo data based on the OpenID claims scopes requested.
-- See <<http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims>>
-- for more information.
--
scopedClaims :: [Scope]    -- ^ The scope present in the access token
             -> UserInfo   -- ^ The fully populated user info data
             -> UserInfo   -- ^ The (possibly) reduced data
scopedClaims scopes user
    | null oicClaims = emailClaims baseClaims -- No specific scope requested
    | otherwise      = foldl' (\u f -> f u) baseClaims oicClaims
  where
    baseClaims = def { sub = sub user }
    oicClaims = foldl' claimsForScope [] scopes

    claimsForScope acc s = case s of
        Profile -> profileClaims : acc
        Email   -> emailClaims : acc
        Phone   -> phoneClaims : acc
        Address -> addressClaims : acc
        _       -> acc

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
        , gender      = gender user
        , birthdate   = birthdate user
        , zoneinfo    = zoneinfo user
        , locale      = locale user
        , updated_at  = updated_at user
        }

    emailClaims   u = u { email        = email user, email_verified = email_verified user }
    addressClaims u = u { address      = address user }
    phoneClaims   u = u { phone_number = phone_number user, phone_number_verified = phone_number_verified user }


scimUserToUserInfo :: Scim.ScimUser -> UserInfo
scimUserToUserInfo scimUser = UserInfo
    { sub         = fromJust $ Scim.scimId scimUser
    , name        = Scim.nameFormatted =<< sn
    , given_name  = Scim.nameGivenName =<< sn
    , family_name = Scim.nameFamilyName =<< sn
    , middle_name = Scim.nameMiddleName =<< sn
    , nickname    = Scim.scimNickName scimUser
    , preferred_username = Nothing -- There isn't a SCIM version of this
    , profile     = Scim.scimProfileUrl scimUser
    , picture     = Nothing
    , website     = Nothing
    , email       = em
    , email_verified = maybe Nothing (\_ -> Just False) em
    , gender      = Nothing
    , birthdate   = Nothing
    , zoneinfo    = Nothing
    , locale      = Scim.scimLocale scimUser
    , phone_number = ph
    , phone_number_verified = maybe Nothing (\_ -> Just False) ph
    , address     = fmap scimAddressToAddress ad
    , updated_at  = Nothing -- scimMeta scimUser >>= lastModified >>= return . M.TokenTime . utcTimeToPOSIXSeconds
    }

  where
    sn = Scim.scimName scimUser
    em = (Scim.emailValue . head) <$> Scim.scimEmails scimUser
    ad = head                     <$> Scim.scimAddresses scimUser
    ph = (Scim.phoneValue . head) <$> Scim.scimPhoneNumbers scimUser

    scimAddressToAddress scimAddr = AddressClaims
        { formatted      = Scim.addrFormatted scimAddr
        , street_address = Scim.addrStreetAddress scimAddr
        , locality       = Scim.addrLocality scimAddr
        , region         = Scim.addrRegion scimAddr
        , postal_code    = Scim.addrPostalCode scimAddr
        , country        = Scim.addrCountry scimAddr
        }
