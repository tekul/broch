{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.Discovery where

import           Data.Aeson
import           Data.Aeson.Types(Options(..), defaultOptions)
import           Data.Text (Text)
import qualified Data.Text as T
import           GHC.Generics (Generic)
import           Jose.Jwa

import           Broch.Model

data OpenIDConfiguration = OpenIDConfiguration
    { issuer :: Text
    , authorization_endpoint :: Text
    , token_endpoint :: Text
    , userinfo_endpoint :: Text
    , jwks_uri :: Text
    , registration_endpoint :: Maybe Text
    , scopes_supported :: [Text]
    , response_types_supported :: [ResponseType]
    , accr_values_supported :: Maybe [Text]    -- What's this?
    , subject_types_supported :: [Text] -- http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
    , id_token_signing_alg_values_supported :: [JwsAlg]
    , id_token_encryption_alg_values_supported :: Maybe [JweAlg]
    , id_token_encryption_enc_values_supported :: Maybe [Enc]
    , user_info_signing_alg_values_supported :: Maybe [JwsAlg]
    , user_info_encryption_alg_values_supported :: Maybe [JweAlg]
    , user_info_encryption_enc_values_supported :: Maybe [Enc]
    , request_object_signing_alg_values_supported :: Maybe [JwsAlg]
    , request_object_encryption_alg_values_supported :: Maybe [JweAlg]
    , request_object_encryption_enc_values_supported :: Maybe [Enc]
    , token_endpoint_auth_methods_supported :: [Text]
    , token_endpoint_auth_signing_alg_values_supported :: Maybe [Alg]
    , display_values_supported :: Maybe [Text]
    , claim_types_supported :: Maybe [Text]
    , claims_supported :: Maybe [Text]
    , service_documentation :: Maybe Text
    , claims_locales_supported :: Maybe [Text]
    , ui_locales_supported :: Maybe [Text]
    , claims_parameter_supported :: Bool
    , request_parameter_supported :: Bool
    , request_uri_parameter_supported :: Bool
    , op_policy_uri :: Maybe Text
    , op_tos_uri :: Maybe Text
    } deriving (Show, Generic)


omitNothingOptions :: Options
omitNothingOptions = defaultOptions { omitNothingFields = True }

instance ToJSON OpenIDConfiguration where
    toJSON = genericToJSON omitNothingOptions

instance FromJSON OpenIDConfiguration where
    parseJSON = genericParseJSON omitNothingOptions

defaultOpenIDConfiguration :: Text -> OpenIDConfiguration
defaultOpenIDConfiguration issuerUrl = OpenIDConfiguration
    { issuer = issuerUrl
    , authorization_endpoint = T.concat [url, "oauth2/authorize"]
    , token_endpoint         = T.concat [url, "oauth2/token"]
    , userinfo_endpoint      = T.concat [url, "connect/user_info"]
    , jwks_uri               = T.concat [url, ".well-known/jwks"]
    , registration_endpoint  = Nothing
    , scopes_supported       = ["openid", "profile", "email"]
    , response_types_supported = [Code, Token, CodeIdToken]
    , accr_values_supported  = Nothing
    , subject_types_supported = ["public"]
    , id_token_signing_alg_values_supported = [RS256, RS384, RS512, HS256, HS384, HS512]
    , id_token_encryption_alg_values_supported = Nothing
    , id_token_encryption_enc_values_supported = Nothing
    , user_info_signing_alg_values_supported = Nothing
    , user_info_encryption_alg_values_supported = Nothing
    , user_info_encryption_enc_values_supported = Nothing
    , request_object_signing_alg_values_supported = Nothing
    , request_object_encryption_alg_values_supported = Nothing
    , request_object_encryption_enc_values_supported = Nothing
    , token_endpoint_auth_methods_supported = ["client_secret_basic"] -- TODO: Create type
    , token_endpoint_auth_signing_alg_values_supported = Nothing
    , display_values_supported = Nothing
    , claim_types_supported = Nothing
    , claims_supported = Nothing
    , service_documentation = Nothing
    , claims_locales_supported = Nothing
    , ui_locales_supported = Nothing
    , claims_parameter_supported = False
    , request_parameter_supported = False
    , request_uri_parameter_supported = False
    , op_policy_uri = Nothing
    , op_tos_uri    = Nothing
    }
 where
    url = case T.last issuerUrl of
        '/' -> issuerUrl
        _   -> issuerUrl `T.snoc` '/'
