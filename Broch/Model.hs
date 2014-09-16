{-# LANGUAGE OverloadedStrings, Rank2Types #-}

module Broch.Model where

import Control.Applicative (pure)
import Crypto.Random (CPRG)
import Data.Aeson
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Maybe (fromJust)
import Data.Time
import Data.Time.Clock.POSIX
import Data.Tuple (swap)
import Jose.Jwt (IntDate)
import Jose.Jwa (JwsAlg)
import Jose.Jwk

type WithCPRG m g = CPRG g => (g -> (a, g)) -> m a

type TokenTTL = NominalDiffTime

type ClientId = Text

-- The unique identifier assigned to a user (typically a UUID)
type SubjectId = Text

class Subject s where
    subjectId :: s -> SubjectId
    authTime  :: s -> POSIXTime


data Scope = OpenID
           | Profile
           | Email
           | Phone
           | Address
           | CustomScope Text
             deriving (Eq, Ord, Show)

scopeName :: Scope -> Text
scopeName s = case s of
    OpenID  -> "openid"
    Profile -> "profile"
    Email   -> "email"
    Phone   -> "phone"
    Address -> "address"
    CustomScope n -> n

scopeDescription :: Scope -> Text
scopeDescription s = case s of
    OpenID  -> "openid"
    Profile -> "access to your profile"
    Email   -> "your email address"
    Phone   -> "your phone number(s)"
    Address -> "your address"
    CustomScope n -> n

scopeFromName :: Text -> Scope
scopeFromName name = case name of
    "openid"  -> OpenID
    "profile" -> Profile
    "email"   -> Email
    "phone"   -> Phone
    "address" -> Address
    n         -> CustomScope n

formatScope :: [Scope] -> Text
formatScope s = T.intercalate " " $ map scopeName s

type LoadClient m = ClientId
                 -> m (Maybe Client)

type CreateAuthorization m s = Text
                            -> s
                            -> Client
                            -> POSIXTime
                            -> [Scope]
                            -> Maybe Text
                            -> Maybe Text
                            -> m ()

type LoadAuthorization m = Text
                        -> m (Maybe Authorization)

type AuthenticateResourceOwner m = Text
                                -> Text
                                -> m (Maybe SubjectId)

type LoadApproval m = SubjectId
                   -> Client
                   -> POSIXTime
                   -> m (Maybe Approval)

type CreateApproval m = Approval
                     -> m ()


type CreateAccessToken m = Maybe SubjectId    -- ^ The end user (resource owner)
                        -> Client             -- ^ The OAuth client the token will be issued to
                        -> GrantType          -- ^ The grant type under which the token was requested
                        -> [Scope]            -- ^ The scope granted to the client
                        -> POSIXTime          -- ^ Current time
                        -> m (ByteString, Maybe ByteString, TokenTTL)

type CreateIdToken m = SubjectId        -- ^ The authenticated user
                    -> Client           -- ^ The client (audience)
                    -> Maybe Text       -- ^ The client submitted nonce
                    -> POSIXTime        -- ^ Current time
                    -> Maybe ByteString -- ^ Authorization code
                    -> Maybe ByteString -- ^ Access token
                    -> m ByteString     -- ^ The token (either a JWS or JWE depending onthe client)

type DecodeRefreshToken m = Client
                         -> Text                  -- ^ The refresh_token parameter
                         -> m (Maybe AccessGrant)

data Authorization = Authorization
    { authzSubject :: !SubjectId
    , authzClient :: !ClientId
    , authzAt :: !IntDate
    , authzScope :: ![Scope]
    , authzNonce :: !(Maybe Text)
    , authzRedirectUri :: !(Maybe Text)
    } deriving (Eq, Show)

data AccessGrant = AccessGrant
    { granterId       :: Maybe SubjectId
    , granteeId       :: ClientId
    , accessGrantType :: GrantType
    , grantScope      :: [Scope]
    , grantExpiry     :: IntDate
    } deriving (Eq, Show)

data Approval = Approval
    { approverId      :: SubjectId   -- The user
    , approvedClient  :: ClientId
    , approvedScope   :: [Scope]
    , approvalExpiry  :: IntDate
    } deriving (Show)


data GrantType = AuthorizationCode
               | RefreshToken
               | ResourceOwner
               | ClientCredentials
               | Implicit
               | JwtBearer         -- ^ <http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-09>
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
-- implicit is invalid, but someone might use it by mistake
    , ("implicit",           Implicit)
    , ("urn:ietf:params:oauth:grant-type:jwt-bearer:", JwtBearer)
    ]

grantTypeNames :: [(GrantType, Text)]
grantTypeNames = map swap grantTypes

grantTypeName :: GrantType -> Text
grantTypeName gt = fromJust $ lookup gt grantTypeNames

data ClientAuthMethod = ClientSecretBasic
                      | ClientSecretPost
                      | ClientSecretJwt
                      | PrivateKeyJwt
                      | ClientAuthNone
                        deriving (Eq, Show, Read)

instance FromJSON ClientAuthMethod where
    parseJSON = withText "ClientAuthMethod" $ \t -> case t of
        "client_secret_basic" -> pure ClientSecretBasic
        "client_secret_post"  -> pure ClientSecretPost
        "client_secret_jwt"   -> pure ClientSecretJwt
        "private_key_jwt"     -> pure PrivateKeyJwt
        "none"                -> pure ClientAuthNone
        _                     -> fail "Unknown or unsupported client auth method"

instance ToJSON ClientAuthMethod where
    toJSON a = case a of
        ClientSecretBasic -> String "client_secret_basic"
        ClientSecretPost  -> String "client_secret_post"
        ClientSecretJwt   -> String "client_secret_jwt"
        PrivateKeyJwt     -> String "private_key_jwt"
        ClientAuthNone    -> String "none"

data Client = Client
    { clientId :: ClientId
    , clientSecret :: Maybe Text
    , authorizedGrantTypes :: [GrantType]
    , redirectURIs :: [Text]
    , accessTokenValidity :: Int
    , refreshTokenValidity :: Int
    , allowedScope :: [Scope]
    , autoapprove :: Bool
    , tokenEndpointAuthMethod :: ClientAuthMethod
    , tokenEndpointAuthAlg    :: Maybe JwsAlg
    , clientKeysUri :: Maybe Text
    , clientKeys    :: Maybe [Jwk]
    } deriving (Show)

data ResponseType = Code
                  | Token
                  | IdTokenResponse
                  | CodeIdToken
                  | CodeToken
                  | TokenIdToken
                  | CodeTokenIdToken
                    deriving (Eq, Show)

responseTypeName :: ResponseType -> Text
responseTypeName t = case t of
    Code  -> "code"
    Token -> "token"
    IdTokenResponse -> "id_token"
    CodeIdToken -> "code id_token"
    CodeToken -> "code token"
    TokenIdToken -> "id_token token"
    CodeTokenIdToken -> "code id_token token"

instance ToJSON ResponseType where
    toJSON = String . responseTypeName

instance FromJSON ResponseType where
    parseJSON = withText "ResponseType" $ \t ->
        maybe (fail "Invalid response type") pure $ lookup t responseTypes

responseTypes :: [(Text, ResponseType)]
responseTypes =
    [ ("code",    Code)
    , ("token",   Token)
    , ("id_token", IdTokenResponse)
    , ("code id_token",  CodeIdToken)
    , ("code token",  CodeToken)
    , ("id_token token", TokenIdToken)
    , ("code id_token token", CodeTokenIdToken)
    ]

