{-# LANGUAGE OverloadedStrings #-}

module Broch.Server.Config where

import           Control.Applicative
import           Control.Error
import           Control.Monad.IO.Class
import           Control.Concurrent.MVar
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.Map as Map
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           Jose.Jwa
import           Jose.Jwk
import           Jose.Jwt

import Broch.Model
import Broch.Random
import Broch.Token


data SupportedAlgorithms = SupportedAlgorithms
    { idTokenSigningAlgs          :: [JwsAlg]
    , idTokenEncryptionAlgs       :: [JweAlg]
    , idTokenEncryptionEncs       :: [Enc]
    , userInfoSigningAlgs         :: [JwsAlg]
    , userInfoEncryptionAlgs      :: [JweAlg]
    , userInfoEncryptionEncs      :: [Enc]
    , requestObjectSigningAlgs    :: [JwsAlg]
    , requestObjectEncryptionAlgs :: [JweAlg]
    , requestObjectEncryptionEncs :: [Enc]
    , clientAuthSigningAlgs       :: [JwsAlg]
    }

defSupportedAlgorithms :: SupportedAlgorithms
defSupportedAlgorithms = SupportedAlgorithms
    { idTokenSigningAlgs = opSigAlgs
    , idTokenEncryptionAlgs = opEncAlgs
    , idTokenEncryptionEncs = opEncEncs
    , userInfoSigningAlgs = opSigAlgs
    , userInfoEncryptionAlgs = opEncAlgs
    , userInfoEncryptionEncs = opEncEncs
    , requestObjectSigningAlgs = opSigAlgs ++ [ES256, ES384, ES512]
    , requestObjectEncryptionAlgs = opEncAlgs
    , requestObjectEncryptionEncs = opEncEncs
    , clientAuthSigningAlgs = opSigAlgs ++ [ES256, ES384, ES512]
    }
  where
    opSigAlgs = [RS256, RS384, RS512, HS256, HS384, HS512]
    opEncAlgs = [RSA1_5, RSA_OAEP]
    opEncEncs = [A128CBC_HS256, A256CBC_HS512, A128GCM, A256GCM]

-- | The configuration data needed to create a Broch server
data Config m s = Config
    { issuerUrl                  :: Text
    , publicKeys                 :: m [Jwk]
    , signingKeys                :: m [Jwk]
    , decryptionKeys             :: m [Jwk]
    , responseTypesSupported     :: [ResponseType]
    , algorithmsSupported        :: SupportedAlgorithms
    , clientAuthMethodsSupported :: [ClientAuthMethod]
    , claimsSupported            :: [Text]
    , createClient               :: CreateClient m
    , getClient                  :: LoadClient m
    , createAuthorization        :: CreateAuthorization m s
    , getAuthorization           :: LoadAuthorization m
    , authenticateResourceOwner  :: AuthenticateResourceOwner m
    , createApproval             :: CreateApproval m
    , getApproval                :: LoadApproval m
    , createAccessToken          :: CreateAccessToken m
    , decodeAccessToken          :: DecodeAccessToken m
    , decodeRefreshToken         :: DecodeRefreshToken m
    , getUserInfo                :: LoadUserInfo m
    }

-- | Creates a configuration using in-memory storage for simple testing.
inMemoryConfig :: (MonadIO m, Subject s)
    -- | The issuer (the external URL used to access your server)
    => Text
    -> IO (Config m s)
inMemoryConfig issuer = do
    clients        <- newMVar Map.empty
    authorizations <- newMVar Map.empty
    approvals      <- newMVar Map.empty
    (sigPub, sigPr) <- generateKeyPair (Signed RS256)
    (encPub, encPr) <- generateKeyPair (Encrypted RSA_OAEP)
    pubKeys        <- newMVar [sigPub, encPub]
    sigKeys        <- newMVar [sigPr]
    decKeys        <- newMVar [encPr]
    let accessTokenEncoding = AlgPrefs Nothing (E RSA_OAEP A128GCM)
        decodeToken t = do
            dKeys <- liftIO (readMVar decKeys)
            liftIO $ withCPRG $ \g -> decodeJwtAccessToken g [] dKeys accessTokenEncoding t

    return Config
        { issuerUrl = issuer
        , publicKeys  = liftIO (readMVar pubKeys)
        , signingKeys = liftIO (readMVar sigKeys)
        , decryptionKeys = liftIO (readMVar decKeys)
        , responseTypesSupported = [Code]
        , algorithmsSupported = defSupportedAlgorithms
        , clientAuthMethodsSupported = [ClientSecretBasic, ClientSecretPost, ClientSecretJwt, PrivateKeyJwt]
        , claimsSupported = ["sub", "iss", "auth_time", "name", "given_name", "family_name", "email"]
        , getClient    = \cid -> liftIO $ Map.lookup cid <$> readMVar clients
        , createClient = \c -> liftIO $ modifyMVar_ clients $ \cs -> return $ Map.insert (clientId c) c cs
        , createAuthorization = \code subj c now scps nonce uri -> do
             let a = Authorization (subjectId subj) (clientId c) (IntDate now) scps nonce uri (authTime subj)
             liftIO $ modifyMVar_ authorizations $ \as -> return $ Map.insert code a as
        , getAuthorization = \code -> liftIO $ modifyMVar authorizations $ \as -> do
             let a = Map.lookup code as
             return (Map.delete code as, a)
        , authenticateResourceOwner = error "authenticateResourceOwner has not been set in Config"
        , createApproval = \a -> liftIO $ modifyMVar_ approvals $ \as -> return $ Map.insert (approverId a, approvedClient a) a as
        , getApproval = \sid c now -> liftIO $ modifyMVar approvals $ \as -> do
            let k = (sid, clientId c)
            case Map.lookup k as of
               Just a -> if approvalExpiry a < IntDate now
                             then return (Map.delete k as, Nothing)
                             else return (as, Just a)
               Nothing -> return (as, Nothing)
        , createAccessToken = \user client gt scp now -> do
            encKeys <- liftIO (readMVar pubKeys)
            tokens <- liftIO $ withCPRG $ \g -> createJwtAccessToken g [] encKeys accessTokenEncoding user client gt scp now
            return $ fmapL (const "Failed to create JWT access token") tokens
        , decodeAccessToken = decodeToken
        , decodeRefreshToken = \_ token -> decodeToken (TE.encodeUtf8 token)
        , getUserInfo = error "getUserInfo has not been set"
        }
  where
    generateKeyPair alg = do
        (kPub, kPr) <- withCPRG $ \g -> RSA.generate g 128 65537
        let use = Just $ case alg of
                        Signed _    -> Sig
                        Encrypted _ -> Enc
        return (RsaPublicJwk kPub (Just "brochkey") use (Just alg),
            RsaPrivateJwk kPr (Just "brochkey") use (Just alg))
