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
checkClientScope :: Client -> Maybe [Scope] -> Either Text [Scope]
checkClientScope client = checkRequestedScope (allowedScope client)

checkRequestedScope :: [Scope] -> Maybe [Scope] -> Either Text [Scope]
checkRequestedScope defaultScope maybeScope = case maybeScope of
  Nothing -> Right defaultScope
  Just askedFor ->
    if null denied
      then return askedFor
      else Left $ T.concat ["Requested scope (", formatScope askedFor,
                           ") exceeds allowed scope (", formatScope defaultScope, ")"]
    where
      granted = askedFor `intersect` defaultScope
      denied  = askedFor \\ granted


requireParam :: Map Text [Text] -> Text -> Either Text Text
requireParam env p = case maybeParam env p of
    Right (Just v) -> Right v
    Right Nothing  -> Left $ T.append "Missing " p
    Left err       -> Left err

maybeParam :: Map Text [Text] -> Text -> Either Text (Maybe Text)
maybeParam env p = case Map.lookup p env of
    Just [""]    -> Left $ prefixMsg "Empty "
    Just [value] -> Right $ Just value
    Just (_:_)   -> Left $ prefixMsg "Duplicate "
    _            -> Right Nothing
  where
    prefixMsg m = T.append m p

maybeParseParam :: Map Text [Text] -> Text -> (Text -> Either Text a) -> Either Text (Maybe a)
maybeParseParam env p f = case maybeParam env p of
    Right (Just v) -> Just <$> f v
    Right Nothing  -> Right Nothing
    Left e         -> Left e
