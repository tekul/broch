{-# LANGUAGE OverloadedStrings #-}

import Database.Persist.Sqlite (createSqlitePool)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp (run)

import Broch.Scotty

main :: IO ()
main = do
    -- Back end storage
    pool <- createSqlitePool "broch.db3" 1
    waiApp <- testBroch pool
    run 3000 $ logStdoutDev waiApp

