{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.Registration where

import           Control.Applicative (pure)
import           Data.Aeson
import           Data.Maybe (fromMaybe)
import           Data.Text (Text)
import           GHC.Generics (Generic)
import           Jose.Jwa

import           Broch.Model

type RegisterClient m = ClientMetaData
                     -> m Client

data AppType = Web | Native deriving (Eq, Show)

instance ToJSON AppType where
    toJSON Web    = String "web"
    toJSON Native = String "native"

instance FromJSON AppType where
    parseJSON = withText "AppType" $ \t -> case t of
        "web" -> pure Web
        "app" -> pure Native
        _     -> fail "Invalid application_type"

data ClientMetaData = ClientMetaData
    { redirect_uris :: [Text]
    , response_types :: Maybe [ResponseType]
    , grant_types :: Maybe [GrantType]
    , application_type :: Maybe AppType
    , contacts :: Maybe [Text]
    , client_name :: Maybe Text
    , logo_uri :: Maybe Text
    , client_uri :: Maybe Text
    , policy_uri :: Maybe Text
    , tos_uri :: Maybe Text
    , jwks_uri :: Maybe Text
    , jwks :: Maybe Text
    , sector_identifier_uri :: Maybe Text
    , subject_type :: Maybe Text
    , id_token_signed_response_alg :: Maybe JwsAlg
    , id_token_encrypted_response_alg :: Maybe JweAlg
    , id_token_encrypted_response_enc :: Maybe Enc
    , userinfo_signed_response_alg :: Maybe JwsAlg
    , userinfo_encrypted_response_alg :: Maybe JweAlg
    , userinfo_encrypted_response_enc :: Maybe Enc
    , request_object_signing_alg :: Maybe JwsAlg
    , request_object_encryption_alg :: Maybe JweAlg
    , request_object_encryption_enc :: Maybe Enc
    , token_endpoint_auth_method :: Maybe ClientAuthMethod
    , token_endpoint_auth_signing_alg :: Maybe JwsAlg
    , default_max_age :: Maybe Int
    , require_auth_time :: Maybe Bool
    , default_acr_values :: Maybe [Text]
    , initiate_login_uri :: Maybe Text
    , request_uris :: Maybe [Text]
    } deriving (Eq, Show, Generic)


makeClient :: ClientId -> Text -> ClientMetaData -> Client
makeClient cid csec md = Client
    { clientId = cid
    , clientSecret = Just csec
    , authorizedGrantTypes = fromMaybe [AuthorizationCode] (grant_types md)
    , redirectURIs = redirect_uris md
    , accessTokenValidity  = 24 * 60 * 60
    , refreshTokenValidity = 30 * 24 * 60 * 60
    , allowedScope = [OpenID]
    , autoapprove = False
    }

instance FromJSON ClientMetaData

instance ToJSON ClientMetaData

