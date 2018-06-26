from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app_db import Category, Base, Item, User

engine = create_engine('sqlite:///onlineshopping.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create dummy user
User2 = User(name="JACK", email="thomas@gmail.com", picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User2)
session.commit()



category7 = Category(name="Cars")

session.add(category7)
session.commit()


Item2 = Item(user_id=2, name="Mercedes", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item2)
session.commit()
Item3 = Item(user_id=2, name="BMW", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item3)
session.commit()
Item4 = Item(user_id=2, name="BYD", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item4)
session.commit()
Item5 = Item(user_id=2, name="FIAT", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item5)
session.commit()
Item6 = Item(user_id=2, name="LADA", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item6)
session.commit()
Item7 = Item(user_id=2, name="HONDA", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item7)
session.commit()
Item8 = Item(user_id=2, name="HYNDHI", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item7)
session.commit()
Item8 = Item(user_id=2, name="AUDI", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item8)
session.commit()
Item9 = Item(user_id=2, name="PROTON", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item9)
session.commit()
Item10 = Item(user_id=2, name="RENAULT", description="car",
                     price="$200",item_state = "new", category=category7)

session.add(Item10)
session.commit()

