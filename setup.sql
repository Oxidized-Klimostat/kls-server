CREATE EXTENSION pgjwt CASCADE;

\set jwt_secret `cat /run/secrets/jwt_secret`
\set auth_pass `cat /run/secrets/auth_pass`

ALTER DATABASE postgres SET "kls.jwt_secret" TO :'jwt_secret';

CREATE SCHEMA api;
CREATE SCHEMA kls;


CREATE TABLE IF NOT EXISTS kls.stations (
  id serial primary key,
  token text not null,
  description text not null,
  created timestamptz not null
);

CREATE TABLE IF NOT EXISTS api.sensor_scd30 (
  station integer,
  ts timestamptz not null DEFAULT now(),
  co2 real not null,
  humidity real not null,
  temperature real not null,
  primary key (station, ts),
  constraint fk_scd30_stations foreign key (station) REFERENCES kls.stations (id)
);

CREATE TABLE IF NOT EXISTS api.sensor_ccs811 (
  station integer,
  ts timestamptz not null DEFAULT now(),
  eco2 integer not null,
  etvoc integer not null,
  primary key (station, ts),
  constraint fk_ccs811_stations foreign key (station) REFERENCES kls.stations (id)
);

SELECT create_hypertable('api.sensor_scd30', 'ts');
SELECT create_hypertable('api.sensor_ccs811', 'ts');


CREATE OR REPLACE FUNCTION api.create_station(description text) RETURNS RECORD AS $$
DECLARE
  station_token text := encode(public.digest(gen_random_uuid()::text, 'sha256'), 'hex');
  ret RECORD;
  station_id integer;
BEGIN
  INSERT INTO kls.stations (token, description, created) VALUES
    (public.crypt(station_token, public.gen_salt('bf')), description, now()) RETURNING id INTO station_id;

  SELECT station_token, station_id INTO ret;
  RETURN ret;
END
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION api.auth_station(check_id integer, check_token text) RETURNS text AS $$
DECLARE
  stored_token text;
  jwt_token text;
BEGIN
  SELECT token FROM kls.stations WHERE id = check_id INTO stored_token;
  IF NOT stored_token = public.crypt(check_token, stored_token) THEN
    raise invalid_password using message = 'invalid station_id or token';
  END IF;

  SELECT public.sign(
    row_to_json(r), current_setting('kls.jwt_secret')
  ) AS token
  FROM (
    SELECT
      'station'::text as role,
      extract(epoch from now())::integer + 300 AS exp
  ) r
  INTO jwt_token;
  RETURN jwt_token;
END
$$ LANGUAGE plpgsql;


CREATE ROLE authenticator noinherit LOGIN PASSWORD :'auth_pass';
CREATE ROLE anon nologin;
CREATE ROLE station nologin;

GRANT USAGE ON SCHEMA api, kls to anon;
GRANT USAGE ON SCHEMA api to station;

GRANT anon TO authenticator;
GRANT station TO authenticator;

GRANT INSERT ON api.sensor_scd30, api.sensor_ccs811 TO station;
GRANT SELECT ON kls.stations TO anon;
GRANT EXECUTE ON FUNCTION api.auth_station TO anon;
