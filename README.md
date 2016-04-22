A Haskell implementation of [OpenID Connect](http://openid.net/connect/).

Building
--------

The easiest option is to use [stack](http://docs.haskellstack.org/en/stable/README/#the-haskell-tool-stack). Follow the instructions there to download and install stack (just adding the stack binary to your path), then

    $ git clone https://github.com/tekul/broch
    $ cd broch

If you don't already have a compatible ghc version installed, you can get stack to install one by running

    $ stack setup

To build the project run

    $ stack build

If all goes well you can then run the command-line server, and start it with a sqlite database

    $ stack exec broch -- --help
    $ stack exec broch -- --back-end=SQLITE --issuer=http://localhost:3000

[![Build Status](https://travis-ci.org/tekul/broch.svg?branch=master)](https://travis-ci.org/tekul/broch)

PostgresSQL Backend
-------------------

By default, `broch` uses a PostgresSQL database for storage. Version 9.5 or greater is required. There are two initialization scripts, `pgdb.sql` and `user.sql` which create the required schema. For a real deployment, you would run postgres as a system service running in the background, but you can also run it manually.

First create a directory to store the data and initialize it, then start the database

    $ initdb brochdb
    $ pg_ctl -D ./brochdb start

Then we run the `psql` client, create a new database and run the initialization scripts

    $ psql -u postgres

    postgres=# create database broch;
    postgres=# \connect broch
    broch=# \i pgdb.sql
    broch=# \i user.sql
    broch=# \q

If all goes well, you should then have a database the server can run against, as well as a test user and a test client application. The default connection string is `dbname=broch` so it should work with the database we just created.

    $ stack exec broch -- --issuer=http://localhost:3000
