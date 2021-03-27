create table user_data(
  user_id     varchar       primary key,
  username    varchar(254)  not null,
  password    varchar(254)  not null,
  phone_no    varchar(10)   not null unique,
  email       varchar(254)  unique,
  joined_time timestamp     not null,
  pin_code varchar(6)       not null
);
