Broch
=====

A Haskell implementation of [OpenID Connect](http://openid.net/connect/).

[![Build Status](https://travis-ci.org/tekul/broch.svg?branch=master)](https://travis-ci.org/tekul/broch)

Building
--------

The easiest option is to use [stack](http://docs.haskellstack.org/en/stable/README/#the-haskell-tool-stack), particularly if you are new to Haskell. Follow the instructions to download and install stack (just adding the stack binary to your path), then

    $ git clone https://github.com/tekul/broch
    $ cd broch

If you don't already have a compatible ghc version installed, you can get stack to install one by running

    $ stack setup

To build the project run

    $ stack build

Running with SQLite
-------------------

If all goes well you can then run the command-line server, and start it with a sqlite database

    $ stack exec broch -- --help
    $ stack exec broch -- --back-end=SQLITE --issuer=http://localhost:3000

The SQLite database creates a `broch.db3` file for the database. It automatically creates the schema and adds a test user (username: "cat", password: "cat") and a client called "app". You should then be able to paste the following authorization request into your browser

    http://localhost:3000/oauth/authorize?client_id=app&state=somerandomstate&response_type=code&redirect_uri=http%3A%2F%2Flocalhost:8080/app

After logging in, you will be redirected to the client app URL with a code parameter. This will give a 404, since the client isn't actually running, but you can use a utility like `curl` to mimic the client's interaction with the token endpoint and exchange the code for an access token.

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

You should then have a database the server can run against, as well as the same test user and client application as for SQLite. The default connection string is `dbname=broch` so it should work with the database we just created.

    $ stack exec broch -- --issuer=http://localhost:3000

