{-# LANGUAGE OverloadedStrings #-}
module Broch.OAuth2.Internal where

import Data.List (intersect, (\\))
import Data.Text (Text)
import Data.Map (Map)

import qualified Data.Map as Map
import qualified Data.Text as T

import Broch.Model

-- Checks the (maybe) requested scope for a client.
-- If nothing, returns the default scope for the client,
-- otherwise checks the client has only requested
-- scopes it is allowed. If it has, the requested scopes are
-- returned, otherwise a (left) error message.
checkClientScope :: Client -> Maybe [Text] -> Either Text [Text]
checkClientScope client = checkRequestedScope (allowedScope client)

checkRequestedScope :: [Text] -> Maybe [Text] -> Either Text [Text]
checkRequestedScope defaultScope maybeScope = case maybeScope of
  Nothing -> Right defaultScope
  Just askedFor ->
    if null denied
      then return askedFor
      else Left "Requested scope exceeds allowed scope"
    where
      granted = askedFor `intersect` defaultScope
      denied  = askedFor \\ granted


requireParam :: Map Text [Text] -> Text -> Either Text Text
requireParam env name = case maybeParam env name of
                          Right (Just v) -> Right v
                          Right Nothing  -> Left $ T.append "Missing " name
                          Left err       -> Left err

maybeParam :: Map Text [Text] -> Text -> Either Text (Maybe Text)
maybeParam env name = case Map.lookup name env of
                          Just [""]    -> Left $ prefixMsg "Empty "
                          Just [value] -> Right $ Just value
                          Just (_:_)   -> Left $ prefixMsg "Duplicate "
                          Nothing      -> Right Nothing
                        where
                          prefixMsg m = T.append m name

