CREATE EXTENSION pgjwt CASCADE;

\set jwt_secret `cat /run/secrets/jwt_secret`
\set auth_pass `cat /run/secrets/auth_pass`

ALTER DATABASE postgres SET "kls.jwt_secret" TO :'jwt_secret';


CREATE TABLE IF NOT EXISTS stations (
  id serial primary key,
  token text not null,
  description text not null,
  created timestamptz not null
);


CREATE OR REPLACE FUNCTION add_station(description text) RETURNS RECORD AS $$
DECLARE
  uuid text := gen_random_uuid();
  ret RECORD;
  station_id integer;
BEGIN
  INSERT INTO stations (token, description, created) VALUES
    (crypt(uuid, gen_salt('bf')), description, now()) RETURNING id INTO station_id;

  SELECT uuid, station_id INTO ret;
  RETURN ret;
END
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION auth_station(check_id integer, check_token text) RETURNS text AS $$
DECLARE
  stored_token text;
  jwt_token text;
BEGIN
  SELECT token FROM stations WHERE id = check_id INTO stored_token;
  IF NOT stored_token = crypt(check_token, stored_token) THEN
    raise invalid_password using message = 'invalid station_id or token';
  END IF;

  SELECT public.sign(
    row_to_json(r), current_setting('kls.jwt_secret')
  ) AS token
  FROM (
    SELECT
      'station'::text as role,
      extract(epoch from now())::integer + 30 AS exp
  ) r
  INTO jwt_token;
  RETURN jwt_token;
END
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION jwt_test() RETURNS text AS $$
  SELECT public.sign(
    row_to_json(r), current_setting('kls.jwt_secret')
  ) AS token
  FROM (
    SELECT
      'my_role'::text as role,
      extract(epoch from now())::integer + 300 AS exp
  ) r;
$$ LANGUAGE sql;


CREATE ROLE anon nologin;

CREATE ROLE authenticator noinherit LOGIN PASSWORD :'auth_pass';
GRANT anon TO authenticator;
