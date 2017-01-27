from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a dummy user
User1 = User(name="Patrick Reid", email="patrick.reid27@example.com",
             picture="https://randomuser.me/api/portraits/men/35.jpg")
session.add(User1)
session.commit()
print("Dummy user added!")

# Create dummy category
cat1 = Category(name="Basketball", user_id=1, user=User1)
session.add(cat1)
session.commit()
print("Dummy category added!")

# Create dummy item
item1 = Item(category_id=1, user=User1, user_id=1, category=cat1, \
             name="Uniform", description="Worn by " \
                                         "the " \
                                         "players "
                                         "to define "
                                         "both teams.")
session.add(item1)
session.commit()
print("Dummy item added!")
