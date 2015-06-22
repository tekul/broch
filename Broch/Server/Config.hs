{-# LANGUAGE OverloadedStrings, RecordWildCards #-}

module Broch.Server.Config where

import           Control.Applicative
import           Control.Concurrent.MVar
import           Control.Error
import           Control.Monad (when)
import           Control.Monad.IO.Class
import           Crypto.Random (withDRG, getSystemDRG)
import qualified Data.Aeson as A
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map as Map
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           Data.Time.Clock
import           Jose.Jwa
import           Jose.Jwk
import           Jose.Jwt
import           System.Directory (doesFileExist)

import Broch.Model
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
    , keyRing                    :: KeyRing m
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

data KeyRing m = KeyRing
    { publicKeys       :: m [Jwk]
    -- ^ Keys which should be returned form the jwks_uri endpoint
    -- (as per 10.1.1 and 10.2.1 of OIC spec). Public signature keys include those
    -- which are expired but may still be used to verify an OP signature. Public
    -- encryption keys only include the current key or keys.
    , signingKeys      :: m [Jwk]
    -- ^ Private keys which the OP uses for signing. Should only include
    -- unexpired keys.
    , decryptionKeys   :: m [Jwk]
    -- ^ Private keys for decryption. Should included both expired
    -- and unexpired keys.
    , rotateKeys       :: Bool -> m ()
    -- ^ Performs a key rotation, creating a new set of keys.
    -- If the boolean parameter is true, the existing keys will be overwritten,
    -- otherwise they will be treated as expired.
    }

data KeyRingParams = KeyRingParams
    { keyRingFile      :: FilePath
    , rsaKeySizeBytes  :: Int
    , keyTTLdays       :: Int
    , gracePeriod      :: Int
    } deriving (Show)


defaultKeyRing :: IO (KeyRing IO)
defaultKeyRing = getKeyRing defaultKeyRingParams

defaultKeyRingParams :: KeyRingParams
defaultKeyRingParams = KeyRingParams "jwks.json" 128 5 5

getKeyRing :: KeyRingParams -> IO (KeyRing IO)
getKeyRing KeyRingParams {..} = do
    now     <- getCurrentTime
    allJwks <- readOrGenerateKeys

    let validJwks = filter (not . isOutOfGrace now) allJwks
        activeKeys = filter (isActive now) validJwks

    serverKeys <- newMVar validJwks

    let filterKeys f = filter f <$> readMVar serverKeys

        rotate overwrite = modifyMVar_ serverKeys $ \ks -> do
            rotateTime <- getCurrentTime
            let ks' = filter (not . isOutOfGrace rotateTime) ks
            newKeys <- generateKeys
            let allKeys = if overwrite then newKeys else newKeys ++ ks'
            saveKeys allKeys
            return allKeys

    -- Default keyring has two active key pairs for signing and encryption
    when (length activeKeys < 4) $ rotate False

    return KeyRing
        { publicKeys = do
            ks <- readMVar serverKeys
            t  <- getCurrentTime
            return $ filter (\k -> isPublic k && (jwkUse k /= Just Enc || isActive t k)) ks
        , signingKeys = take 1 <$> filterKeys isSigningKey
        , decryptionKeys = filterKeys isDecryptionKey
        , rotateKeys = rotate
        }
  where
    secondsPerDay = 24 * 60 * 60

    isActive now = not . isOlderThan keyTTLdays now
    isSigningKey k = isPrivate k && jwkUse k == Just Sig
    isDecryptionKey k = isPrivate k && jwkUse k == Just Enc
    isOutOfGrace = isOlderThan (keyTTLdays + gracePeriod)

    isOlderThan nDays now k = case jwkId k of
        Just (UTCKeyId t) -> addUTCTime (fromIntegral $ nDays * secondsPerDay) t < now
        _                 -> False

    readOrGenerateKeys :: IO [Jwk]
    readOrGenerateKeys = do
        exists <- doesFileExist keyRingFile
        jwks   <- if exists
                      then A.decodeStrict <$> B.readFile keyRingFile
                      else return Nothing
        case jwks of
            Just (JwkSet ks) -> return ks
            Nothing          -> do
                ks  <- generateKeys
                saveKeys ks
                return ks

    saveKeys ks = BL.writeFile keyRingFile (A.encode (JwkSet ks))

    generateKeys = do
        now <- getCurrentTime
        (sigPub, sigPr) <- generateRsaKeyPair rsaKeySizeBytes (UTCKeyId now) Sig Nothing
        (encPub, encPr) <- generateRsaKeyPair rsaKeySizeBytes (UTCKeyId (addUTCTime 1 now)) Enc Nothing
        return [sigPub, sigPr, encPub, encPr]

-- | Creates a configuration using in-memory storage for simple testing.
inMemoryConfig :: (MonadIO m, Subject s)
    -- | The issuer (the external URL used to access your server)
    => Text
    -> KeyRing m
    -> IO (Config m s)
inMemoryConfig issuer kr = do
    clients        <- newMVar Map.empty
    authorizations <- newMVar Map.empty
    approvals      <- newMVar Map.empty
    let accessTokenEncoding = AlgPrefs Nothing (E RSA_OAEP A128GCM)
        decodeToken t = do
            dKeys <- decryptionKeys kr
            rng <- liftIO getSystemDRG
            let (grant, _) = withDRG rng (decodeJwtAccessToken [] dKeys accessTokenEncoding t)
            return grant

    return Config
        { issuerUrl  = issuer
        , keyRing = kr
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
            encKeys <- publicKeys kr
            rng     <- liftIO getSystemDRG
            let (tokens, _) = withDRG rng (createJwtAccessToken [] encKeys accessTokenEncoding user client gt scp now)
            return $ fmapL (const "Failed to create JWT access token") tokens
        , decodeAccessToken = decodeToken
        , decodeRefreshToken = \_ token -> decodeToken (TE.encodeUtf8 token)
        , getUserInfo = error "getUserInfo has not been set"
        }
