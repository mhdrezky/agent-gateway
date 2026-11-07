-- Sample data for the sql broker tests. The reader login may also INSERT into
-- product, so a test can show that the read-only session blocks writes on its own.
CREATE SCHEMA sample;

CREATE TABLE sample.product (
    id integer PRIMARY KEY,
    name text NOT NULL,
    price numeric(10, 2) NOT NULL,
    added_on date NOT NULL,
    tags text[] NOT NULL DEFAULT '{}',
    attrs jsonb NOT NULL DEFAULT '{}'
);

CREATE TABLE sample.customer (
    id integer PRIMARY KEY,
    email text NOT NULL
);

-- A decoy with an allowed name in another schema: the gate pins to sample.
CREATE TABLE public.product (id integer PRIMARY KEY, name text NOT NULL);
INSERT INTO public.product VALUES (1, 'decoy');

INSERT INTO sample.product (id, name, price, added_on, tags, attrs)
SELECT i, 'product ' || i, i * 1.25, DATE '2026-01-01' + i, ARRAY['t' || i], jsonb_build_object('n', i)
FROM generate_series(1, 25) AS i;

INSERT INTO sample.customer VALUES (1, 'someone@example.com');

CREATE ROLE agw_reader LOGIN PASSWORD 'reader-pa55-for-tests';
GRANT CONNECT ON DATABASE sales TO agw_reader;
GRANT USAGE ON SCHEMA sample TO agw_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA sample TO agw_reader;
GRANT INSERT ON sample.product TO agw_reader;
GRANT SELECT ON public.product TO agw_reader;
