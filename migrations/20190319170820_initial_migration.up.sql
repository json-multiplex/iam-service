CREATE TABLE accounts (
  id UUID NOT NULL PRIMARY KEY,
  create_time TIMESTAMP WITH TIME ZONE NOT NULL,
  update_time TIMESTAMP WITH TIME ZONE NOT NULL,
  delete_time TIMESTAMP WITH TIME ZONE,
  display_name TEXT NOT NULL
);

CREATE TABLE users (
  id UUID NOT NULL PRIMARY KEY,
  slug TEXT NOT NULL,
  account_id UUID NOT NULL REFERENCES accounts(id),
  create_time TIMESTAMP WITH TIME ZONE NOT NULL,
  update_time TIMESTAMP WITH TIME ZONE NOT NULL,
  delete_time TIMESTAMP WITH TIME ZONE,
  is_root BOOLEAN NOT NULL,
  display_name TEXT NOT NULL
);

CREATE TYPE auth_method AS ENUM('password');

CREATE TABLE identities (
  id UUID NOT NULL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  create_time TIMESTAMP WITH TIME ZONE NOT NULL,
  update_time TIMESTAMP WITH TIME ZONE NOT NULL,
  delete_time TIMESTAMP WITH TIME ZONE,
  auth_method auth_method NOT NULL,
  password_hash TEXT
);
