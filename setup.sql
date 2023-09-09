CREATE EXTENSION pgjwt CASCADE;

\set jwt_secret `cat /run/secrets/jwt_secret`
\set auth_pass `cat /run/secrets/auth_pass`

ALTER DATABASE postgres SET "kls.jwt_secret" TO :'jwt_secret';

CREATE TYPE jwt_token AS (
  token text
);

CREATE OR REPLACE FUNCTION jwt_test() RETURNS public.jwt_token AS $$
  SELECT public.sign(
    row_to_json(r), current_setting('kls.jwt_secret')
  ) AS token
  FROM (
    SELECT
      'my_role'::text as role,
      extract(epoch from now())::integer + 300 AS exp
  ) r;
$$ LANGUAGE sql;

CREATE TABLE todos (
    id SERIAL PRIMARY KEY,
    done BOOLEAN NOT NULL DEFAULT false,
    task TEXT NOT NULL,
    due TIMESTAMPTZ
);
INSERT INTO todos (task) VALUES
    ('finish tutorial 0'), ('pat self on back');

CREATE ROLE anon nologin;
GRANT SELECT ON todos TO anon;

CREATE ROLE authenticator noinherit LOGIN PASSWORD :'auth_pass';
GRANT anon TO authenticator;
