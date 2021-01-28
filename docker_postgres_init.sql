create table user_data(
  user_id varchar primary key,
  username varchar(254) not null,
  password varchar(254) not null,
  phone_no varchar(10) not null,
  email varchar(254) not null,
  pin_code varchar(6) not null,
  is_mail_verified boolean not null
);
