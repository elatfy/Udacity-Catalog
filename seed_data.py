from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Category, User, Item
import json

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()


# users
users_json = json.loads("""{
  "all_users": [
    {
      "name": "Robo Barista",
      "email": "tinnyTim@udacity.com",
      "picture": "https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png"
    },
   {
      "name": "Welly Wally",
      "email": "tinnyTim@udacity.com",
      "picture": "https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png"
    }]
    	}""")


for e in users_json['all_users']:
    user = User(name=str(e['name']), email=str(
        e['email']), picture=str(e['picture']))
    session.add(user)
    session.commit()

# Categories
cats_json = json.loads("""{
  "all_cats": [
    {
      "name":"Music Instruments",
      "user_id":1
    },
    {
      "name":"Basic Items",
      "user_id":2
    }]
    	}""")

for e in cats_json['all_cats']:
    category = Category(name=str(e['name']), user_id=e['user_id'])
    session.add(category)
    session.commit()


# Items
items_json = json.loads("""{
  "all_items": [
    {
      "name":"Guitar",
      "description":"This is Guitar",
      "user_id":1,
      "category_id": 1
    },
    {
      "name":"Very Basic Item",
      "description":"This is a Very Basic Item",
      "user_id":2,
      "category_id": 2
    }]
    }""")

for e in items_json['all_items']:
    item = Item(name=str(e['name']), description=str(e['description']),
                category_id=e['category_id'], user_id=e['user_id'])
    session.add(item)
    session.commit()


print "Added Seed Data"
