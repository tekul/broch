{-# LANGUAGE QuasiQuotes, TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving #-}

module Broch.Persist
    ( migrateAll
    , createAuthorization
    , getAuthorizationByCode
    )
where

import Control.Monad (void)
import Database.Persist (insert, getBy, delete, Entity(..), PersistStore)
import Database.Persist.TH (share, sqlSettings, mkMigrate, mkPersist, persistLowerCase)

import Data.Text (Text)
import Data.Time.Clock.POSIX

import Broch.Model

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
AuthCode
  code   Text
  uid    Text
  client Text
  issueAt Int
  scope  [Text]
  uri    Text Maybe
  UniqueCode code
  deriving Show
|]


createAuthorization :: (Functor f, PersistStore f) => Text -> Text -> Client -> POSIXTime -> [Text] -> Maybe Text -> f ()
createAuthorization code userId client now scope mURI =
    void (insert $ AuthCode code userId (clientId client) (fromIntegral $ round now) scope mURI)

getAuthorizationByCode code = do
    record <- getBy $ UniqueCode code
    case record of
        Nothing -> return Nothing
        Just (Entity key (AuthCode _ uid client issueAt scope uri)) -> do
            delete key
            return $ Just $ Authorization uid client (fromIntegral issueAt) scope uri

