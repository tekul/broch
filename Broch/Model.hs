{-# LANGUAGE OverloadedStrings #-}

module Broch.Model where

import Control.Applicative (pure)
import Data.Aeson
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Maybe (fromJust)
import Data.Time
import Data.Time.Clock.POSIX
import Data.Tuple (swap)

type TokenTTL = NominalDiffTime

type OAuth2User = Text
type ClientId = Text

data Scope = OpenID
           | Profile
           | Email
           | Phone
           | Address
           | CustomScope Text
             deriving (Eq, Show)

scopeName s = case s of
    OpenID  -> "openid"
    Profile -> "profile"
    Email   -> "email"
    Phone   -> "phone"
    Address -> "address"
    CustomScope n -> n

scopeDescription s = case s of
    OpenID  -> "openid"
    Profile -> "access to your profile"
    Email   -> "your email address"
    Phone   -> "your phone number(s)"
    Address -> "your address"
    CustomScope n -> n

scopeFromName n = case n of
    "openid"  -> OpenID
    "profile" -> Profile
    "email"   -> Email
    "phone"   -> Phone
    "address" -> Address
    n         -> CustomScope n

type LoadClient m = ClientId
                 -> m (Maybe Client)

type CreateAuthorization m = Text
                          -> OAuth2User
                          -> Client
                          -> POSIXTime
                          -> [Scope]
                          -> Maybe Text
                          -> m ()

type LoadAuthorization m = Text
                        -> m (Maybe Authorization)

type AuthenticateResourceOwner m = Text
                                -> Text
                                -> m (Maybe OAuth2User)

type LoadApproval m = Text
                   -> Client
                   -> POSIXTime
                   -> m (Maybe Approval)

type CreateApproval m = Approval
                     -> m ()


type CreateAccessToken m = Maybe OAuth2User   -- ^ The end user (resource owner)
                        -> Client             -- ^ The OAuth client the token will be issued to
                        -> GrantType          -- ^ The grant type under which the token was requested
                        -> [Scope]            -- ^ The scope granted to the client
                        -> POSIXTime          -- ^ Current time
                        -> m (ByteString, Maybe ByteString, TokenTTL)

type DecodeRefreshToken m = Client
                       -> Text
                       -> m (Maybe AccessGrant)


data Authorization = Authorization
    { authorizedSubject :: OAuth2User
    , authorizedClient :: ClientId
    , authorizedAt :: POSIXTime
    , authorizedScope :: [Scope]
    , authorizedRedirectUri :: Maybe Text
    } deriving (Eq, Show)

data AccessGrant = AccessGrant
    { granterId    :: Maybe Text
    , granteeId    :: ClientId
    , accessGrantType    :: GrantType
    , grantScope   :: [Scope]
    , grantExpiry  :: POSIXTime
    } deriving (Eq, Show)

data Approval = Approval
    { approverId :: Text -- The user
    , approvedClient :: ClientId
    , approvedScope :: [Scope]
    , approvalExpiry :: POSIXTime
    } deriving (Show)


data GrantType = AuthorizationCode
               | RefreshToken
               | Implicit
               | ResourceOwner
               | ClientCredentials
                 deriving (Show, Read, Eq)

instance ToJSON GrantType where
    toJSON = String . grantTypeName

instance FromJSON GrantType where
    parseJSON = withText "GrantType" $ \g ->
        maybe (fail "Invalid grant type") pure $ lookup g grantTypes

-- | Lookup table to convert grant_type request parameter to GrantType
grantTypes :: [(Text, GrantType)]
grantTypes =
    [ ("authorization_code", AuthorizationCode)
    , ("refresh_token",      RefreshToken)
    , ("password",           ResourceOwner)
    , ("client_credentials", ClientCredentials)
    ]

grantTypeNames :: [(GrantType, Text)]
grantTypeNames = map swap grantTypes

grantTypeName :: GrantType -> Text
grantTypeName gt = fromJust $ lookup gt grantTypeNames

data Client = Client
    { clientId :: ClientId
    , clientSecret :: Maybe Text
    , authorizedGrantTypes :: [GrantType]
    , redirectURIs :: [Text]
    , accessTokenValidity :: Int
    , refreshTokenValidity :: Int
    , allowedScope :: [Scope]
    , autoapprove :: Bool
    , roles :: [Text]
    }

data ResponseType = Code
                  | Token
                  | IdToken
                  | CodeIdToken
                  | TokenIdToken
                  | CodeTokenIdToken
                    deriving (Eq, Show)

instance ToJSON ResponseType where
    toJSON t = String $ case t of
                          Code  -> "code"
                          Token -> "token"
                          IdToken -> "id_token"
                          CodeIdToken -> "code id_token"
                          TokenIdToken -> "id_token token"
                          CodeTokenIdToken -> "code id_token token"

instance FromJSON ResponseType where
    parseJSON = withText "ResponseType" $ \t ->
        maybe (fail "Invalid response type") pure $ lookup t responseTypes

responseTypes :: [(Text, ResponseType)]
responseTypes =
    [ ("code",    Code)
    , ("token",   Token)
    , ("id_token", IdToken)
    , ("code id_token",  CodeIdToken)
    , ("id_token token", TokenIdToken)
    , ("code id_token token", CodeTokenIdToken)
    ]


