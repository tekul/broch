{-# LANGUAGE OverloadedStrings #-}

-- | URI utilities
--
-- Provides convenient types and functions while hiding the dependency
-- on an external URI library (uri-bytestring) and adding extra restrictions
-- on permissible URI formats.

module Broch.URI
    ( URI
    , parseURI
    , renderURI
    , SectorIdentifier
    , addQueryParams
    , setFragmentParams
    , getSectorIdentifier
    )
where

import           Control.Error (fmapL)
import           Control.Monad (unless)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import           Data.Monoid ((<>))
import           Data.List (nub)
import           Data.Maybe (isJust, isNothing)
import           Data.Text (Text)
import qualified Data.Text.Encoding as TE
import           Network.HTTP.Types (renderSimpleQuery)
import qualified URI.ByteString as U hiding (URI)

-- | URI type.
newtype URI = URI { toURI :: U.URIRef U.Absolute } deriving (Eq)

instance Show URI where
    show = BC.unpack . renderURI

-- | The sector identifier for a client.
-- Used to map subject identifiers to a different unique set on a per-client
-- basis, to avoid sharing of user data between different clients.
-- It is either the host component of the sector_identifier_uri submitted at registration
-- or the host component of the redirect_uri(s) of the client.
type SectorIdentifier = Text

renderURI :: URI -> ByteString
renderURI (URI u) = U.serializeURIRef' u

parseURI :: Text -> Either Text URI
parseURI u = do
    uri <- fmapL (const "Failed to parse URI") (U.parseURI U.strictURIParserOptions (TE.encodeUtf8 u))
    unless (isNothing (U.uriFragment uri)) $ Left "URI contains a fragment"
    unless (isJust (U.uriAuthority uri))   $ Left "URI has no authority component"
    return (URI uri)

addQueryParams :: URI -> [(ByteString, ByteString)] -> URI
addQueryParams (URI u) params =
    let q = U.uriQuery u
     in URI $ u { U.uriQuery = q <> U.Query params}

setFragmentParams :: URI -> [(ByteString, ByteString)] -> URI
setFragmentParams (URI u) params = URI $ u { U.uriFragment = Just (renderSimpleQuery False params) }

getSectorIdentifier :: Maybe URI -> [URI] -> Either Text SectorIdentifier
getSectorIdentifier (Just (URI u)) _      = return (sectorIdentifierFromURI u)
getSectorIdentifier Nothing        uris   = case hosts of
    [h] -> Right h
    []  -> Left "Unable to calculate sector identifier: no redirect_uri set"
    _   -> Left "Unable to calculate sector identifier: redirect_uri hosts are not unique"
  where
    hosts = nub (map (sectorIdentifierFromURI . toURI) uris)

sectorIdentifierFromURI :: U.URIRef U.Absolute -> SectorIdentifier
sectorIdentifierFromURI uri = let Just a = U.uriAuthority uri in TE.decodeUtf8 $ U.hostBS (U.authorityHost a)
