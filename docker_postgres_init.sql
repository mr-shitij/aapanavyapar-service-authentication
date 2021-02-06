create table user_data(
  user_id varchar primary key,
  username varchar(254) not null,
  password varchar(254) not null,
  phone_no varchar(10) not null unique,
  email varchar(254),
  pin_code varchar(6) not null
);

insert into user_data (user_id, username, password, phone_no, email, pin_code) values ('1234', 'shitij', '1234567890', '1234567890', 'shitij@mail.com', '425107');