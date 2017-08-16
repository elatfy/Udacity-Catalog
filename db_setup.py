import datetime
from sqlalchemy import Column, ForeignKey, Integer, String,DateTime,Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    created_date = Column(DateTime, default=datetime.datetime.utcnow)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'email'        : self.email,
           'picture'      : self.picture,
           'created_date' : self.created_date.strftime("%A  %d %b %Y %I:%M%p")
       }

class Category(Base):
    __tablename__ = 'category'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer,ForeignKey('user.id'))
    user = relationship(User)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    items = relationship('Item', cascade='all,delete')


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'created_date' : self.created_date.strftime("%A  %d %b %Y %I:%M%p")
       }
 
class Item(Base):
    __tablename__ = 'item'

    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description = Column(String(250))
    category_id = Column(Integer,ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer,ForeignKey('user.id'))
    user = relationship(User)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    
    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'  : self.description,
           'id'           : self.id,
           'created_date' : self.created_date.strftime("%A  %d %b %Y %I:%M%p")
       }



engine = create_engine('sqlite:///catalog.db')
 

Base.metadata.create_all(engine)
