{-# LANGUAGE OverloadedStrings, DeriveGeneric, Rank2Types #-}

module Broch.Model where

import Control.Applicative (pure)
import Crypto.Random (CPRG)
import Data.Aeson
import Data.Aeson.Types
import Data.Default.Generics
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Maybe (fromJust)
import Data.Time
import Data.Time.Clock.POSIX
import Data.Tuple (swap)
import GHC.Generics
import Jose.Jwt (Jwt, JwtError, IntDate)
import Jose.Jwa (JwsAlg, JweAlg, Enc)
import Jose.Jwk

type WithCPRG m g = CPRG g => (g -> (a, g)) -> m a

type TokenTTL = NominalDiffTime

type ClientId = Text

type Nonce    = Text

-- | The unique identifier assigned to a user (typically a UUID).
type SubjectId = Text

-- | Represents an authenticated user.
class Subject s where
    subjectId :: s -> SubjectId
    authTime  :: s -> POSIXTime

-- | Standard scopes supported by OpenID Connect.
--
-- Other requested scopes which are not part of the standard
-- will be created using the @CustomScope@ constructor.
data Scope
    = OpenID
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
scopeFromName n = case n of
    "openid"  -> OpenID
    "profile" -> Profile
    "email"   -> Email
    "phone"   -> Phone
    "address" -> Address
    nm        -> CustomScope nm

formatScope :: [Scope] -> Text
formatScope s = T.intercalate " " $ map scopeName s

-- | Load a client by ID.
type LoadClient m
     = ClientId
    -> m (Maybe Client)

-- | Creates a new client.
--
-- Called by the client registration endpoint.
type CreateClient m
     = Client
    -> m ()

-- | Stores the data for a successful authorization code request
-- so that it can be loaded later at the token endpoint.
type CreateAuthorization m s
     = Text
    -> s
    -> Client
    -> POSIXTime
    -> [Scope]
    -> Maybe Nonce
    -> Maybe Text
    -> m ()

type LoadAuthorization m
     = Text
    -> m (Maybe Authorization)

-- | Authenticate the user using the resource owner password grant.
--
-- <http://tools.ietf.org/html/rfc6749#section-1.3.3>.
type AuthenticateResourceOwner m
    -- | The username
     = Text
    -- | The plaintext password, submitted by the client
    -> Text
    -> m (Maybe SubjectId)

-- | Find the authorization consent (approval) granted by a user to a client.
--
-- Called at the authorization endpoint to check whether the user has already
-- granted the requested access. If not, they will be prompted to make the
-- decision whether to approve the grant or not, or to approve a subset of the
-- requested scope.
type LoadApproval m
    -- | The end user (resource owner) who approved the request
     = SubjectId
    -- | The client to which the user granted access
    -> Client
    -- | The current time, to check for expiry
    -> POSIXTime
    -- | The approval if it exists and has not expired
    -> m (Maybe Approval)

type CreateApproval m
     = Approval
    -> m ()

type CreateAccessToken m
    -- | The end user (resource owner)
     = Maybe SubjectId
    -- | The OAuth client the token will be issued to
    -> Client
    -- | The grant type under which the token was requested
    -> GrantType
    -- | The scope granted to the client
    -> [Scope]
    -- | Current time
    -> POSIXTime
    -> m (Either Text (ByteString, Maybe ByteString, TokenTTL))

type CreateIdToken m
    -- | The authenticated user
     = SubjectId
    -- | The authentication time
    -> POSIXTime
    -- | The client (audience)
    -> Client
    -- | The client submitted nonce
    -> Maybe Text
    -- | Current time
    -> POSIXTime
    -- | Authorization code
    -> Maybe ByteString
    -- | Access token
    -> Maybe ByteString
    -- | The token (either a JWS or JWE depending on the client)
    -> m (Either JwtError Jwt)

-- | Converts the access token submitted by a client into the access grant data.
--
-- Depending on the token creation function, this may involve decoding the information
-- from the token (if the token is a JWT, for example) or loading the data from persistent
-- storage.
type DecodeAccessToken m
    -- | The token as submitted by the client
     = ByteString
    -- | The access grant if the token is valid
    -> m (Maybe AccessGrant)

-- | Converts a refresh token submitted by a client into the corresponding access grant data.
type DecodeRefreshToken m
    -- | The authenticated client submitting the request
     = Client
    -- | The refresh_token parameter
    -> Text
    -- | The access grant if the token is valid
    -> m (Maybe AccessGrant)

-- | Obtains the currently authenticated user
--
-- This function will usually be written in a web handler monad and will
-- short-circuit if the user is not authenticated, redirecting to a login
-- page if the user is not authenticated, and then re-instating the original request.
type LookupAuthenticatedUser m s = Subject s => m s

-- | Loads the data for a user info response
type LoadUserInfo m
    -- | The authenticated user whose data is being requested
     = SubjectId
    -- | The client to whom the user is being authenticated
    -> Client
    -- | The user info data
    -> m UserInfo

data Authorization = Authorization
    { authzSubject :: !SubjectId
    , authzClient :: !ClientId
    , authzAt :: !IntDate
    , authzScope :: ![Scope]
    , authzNonce :: !(Maybe Text)
    , authzRedirectUri :: !(Maybe Text)
    , authzAuthTime :: !POSIXTime
    } deriving (Eq, Show)

data AccessGrant = AccessGrant
    { granterId       :: Maybe SubjectId
    , granteeId       :: ClientId
    , accessGrantType :: GrantType
    , grantScope      :: [Scope]
    , grantExpiry     :: IntDate
    } deriving (Eq, Show)

data Approval = Approval
    { approverId      :: SubjectId
    , approvedClient  :: ClientId
    , approvedScope   :: [Scope]
    , approvalExpiry  :: IntDate
    } deriving (Show)


data GrantType
    = AuthorizationCode
    | RefreshToken
    | ResourceOwner
    | ClientCredentials
    | Implicit
    -- | <http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-09>
    | JwtBearer
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

data ClientAuthMethod
    = ClientSecretBasic
    | ClientSecretPost
    | ClientSecretJwt
    | PrivateKeyJwt
    | ClientAuthNone
    deriving (Generic, Eq, Show, Read)

instance Default ClientAuthMethod where
    def = ClientSecretBasic

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
    , clientKeysUri  :: Maybe Text
    , clientKeys     :: Maybe [Jwk]
    , idTokenAlgs    :: Maybe AlgPrefs
    , userInfoAlgs   :: Maybe AlgPrefs
    , requestObjAlgs :: Maybe AlgPrefs
    } deriving (Generic, Show)

instance Default Client

type MT = Maybe Text

data AddressClaims = AddressClaims
    { formatted      :: !MT
    , street_address :: !MT
    , locality       :: !MT
    , region         :: !MT
    , postal_code    :: !MT
    , country        :: !MT
    } deriving (Generic, Show)

data UserInfo = UserInfo
    { sub                :: !SubjectId
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

data JwePrefs = E JweAlg Enc
              | NotEncrypted
              deriving (Show, Generic)

data AlgPrefs = AlgPrefs (Maybe JwsAlg) JwePrefs deriving (Show, Generic)

instance ToJSON JwePrefs
instance FromJSON JwePrefs
instance ToJSON AlgPrefs
instance FromJSON AlgPrefs

-- | Standard OAuth2 "code" and "token" response types and
-- OpenID connect "hybrid" response types.
data ResponseType
    = Code
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
