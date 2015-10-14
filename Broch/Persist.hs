{-# LANGUAGE OverloadedStrings #-}

module Broch.Persist where

import           Control.Monad.State.Strict
import qualified Crypto.KDF.BCrypt as BCrypt
import           Data.Maybe (fromJust)
import qualified Data.Text.Encoding as TE
import           Database.Persist.Sql (ConnectionPool, runSqlPersistMPool)

import           Broch.Server.Config
import           Broch.Model hiding (Email)
import           Broch.OpenID.UserInfo
import qualified Broch.Persist.Internal as BP

persistBackend :: (MonadIO m, Subject s) => ConnectionPool -> Config m s -> Config m s
persistBackend pool config =
    let runDB = flip runSqlPersistMPool pool
        createAuthz code usr clnt now scp n uri = liftIO . runDB $
                            BP.createAuthorization code usr clnt now scp n uri
        authenticate username password = do
            u <- liftIO . runDB $ BP.getUserByUsername username
            return $ case u of
                Nothing          -> Nothing
                Just (uid, hash) -> if BCrypt.validatePassword (TE.encodeUtf8 password) (TE.encodeUtf8 hash)
                                        then Just uid
                                        else Nothing
        saveApproval a = runDB $ BP.createApproval a
        loadApproval uid clnt now = liftIO . runDB $ BP.getApproval uid (clientId clnt) now

        loadUserInfo uid _ = do
            scimUser <- (liftIO . runDB . BP.getUserById) uid
            -- Convert from SCIM... yuk
            return $ scimUserToUserInfo (fromJust scimUser)

    in  config
        { getClient = liftIO . runDB . BP.getClientById
        , createClient = liftIO . runDB . BP.createClient
        , createAuthorization = createAuthz
        , getAuthorization = liftIO . runDB . BP.getAuthorizationByCode
        , createApproval = liftIO . saveApproval
        , authenticateResourceOwner = authenticate
        , getApproval = loadApproval
        , getUserInfo = loadUserInfo
        }
