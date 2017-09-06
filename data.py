#!/usr/bin/env python3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Restaurant, Base, MenuItem, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

user1 = User(name="Chetanya Shrimali", email="chetanyashrimalie5@gmail.com")
session.add(user1)
session.commit()
# Menu for UrbanBurger
restaurant1 = Restaurant(name="Urban Burger", user_id=1)

session.add(restaurant1)
session.commit()

menuItem2 = MenuItem(name="Veggie Burger",
                     description="Juicy grilled veggie patty with "
                                 "tomato mayo and lettuce",
                     price="$7.50", course="Entree", restaurant_id=1,
                     user_id=1)

session.add(menuItem2)
session.commit()

print("added items!!")
