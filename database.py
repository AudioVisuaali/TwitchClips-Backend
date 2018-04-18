from sqlalchemy import (Table, Column, String, Integer, Boolean, ForeignKey,
                        Date, select, literal, and_, DateTime, text, Text,
                        exists, create_engine, update,
                        func, desc)
from sqlalchemy.orm import sessionmaker, joinedload, relationship
from sqlalchemy.sql import exists, and_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from utils import commit
import hashlib, uuid

Base = declarative_base()

class Database:

    def __init__(self):
        pass

    def set_credentials(self, type_, username, password, address, database):

        self.type_ = type_
        self.username = username
        self.password = password
        self.address = address
        self.database = database

    def connect(self):

        self.addr = '{0.type_}://{0.username}:{0.password}@{0.address}/{0.database}'.format(self)

        self.engine = create_engine(self.addr, echo=False, convert_unicode=True)

        Base.metadata.create_all(self.engine)

        Session = sessionmaker(bind=self.engine)
        self.session = Session()

        self.user = User(self.session)
        self.clip = Clip(self.session)
        self.tag = Tag(self.session)
        self.sess = Sess(self.session)

    def commit(self):
        self.session.commit()

    def close(self):
        self.session.close()

    def dispose(self):
        self.engine.dispose()

    def user_logged_in(self, remote_addr, user_agent, user_id, session_hash):

        user = self.user.get_by_id(user_id)

        if not user:
            return False, "no user"

        sessions = self.sess.get(user.id)

        for session in sessions:

            hash_ = self.user.hash_(remote_addr + user_agent, session.session_salt)

            if hash_ == session_hash:
                return True, "active"

        return False, "inactive"

class User():

    def __init__(self, session):

        self.session = session

    def create(self, username, password):

        password = self.create_hash(password)

        thing = Users(username, password.salt, password.hash)

        self.session.add(thing)

        try:
            self.session.commit()
            return True, "success"

        except IntegrityError:
            self.session.rollback()
            return False, "duplicate"
        except:
            self.session.rollback()
            return False, "Unknown"

    def login(self, username, password, remote_addr, user_agent):

        user = self.get(username)

        if not user:
            return False

        thing = self.check_login(password, user.password_salt, user.password_hash)

        if not thing:
            return False

        salt = self.create_salt()
        hash_ = self.hash_(remote_addr + user_agent, salt)

        if not thing:
            return False

        class Sethead:
            def __init__(self, hash_, salt, user_id):
                self.hash_ = hash_
                self.salt = salt
                self.user_id = user_id

        return Sethead(hash_, salt, user.id)

    def get(self, username):

        try:
            return self.session.query(Users).filter(Users.username == username).one()
        except:
            return None

    def get_by_id(self, user_id):
        try:
            return self.session.query(Users).filter(Users.id == user_id).one()
        except:
            return None

    def create_salt(self):

        return uuid.uuid4().hex

    def hash_(self, password, salt):

        password = password.encode('utf-8')
        salt = salt.encode('utf-8')

        return hashlib.sha512(password + salt).hexdigest()

    def create_hash(self, password):

        salt = self.create_salt()

        hashed = self.hash_(password, salt)

        class Password:
            def __init__(self, salt, hashed):
                self.salt = salt
                self.hash = hashed

        return Password(salt, hashed)

    def check_login(self, password, salt, hashed):

        thing = self.hash_(password, salt)

        if thing == hashed:
            return True
        return False

class Clip:

    def __init__(self, session):

        self.session = session

    def add(self, user, clip_channel_name, clip_title, clip_identifier, clip_thumbnail):

        thing = Clips(clip_channel_name, clip_title, clip_identifier, clip_thumbnail)

        user.children.append(thing)

        try:
            self.session.commit()
            return True, "success"

        except IntegrityError:
            self.session.rollback()
            return False, "duplicate"

        else:
            self.session.rollback()
            return False, "Unknown"


    def get(self, user_id, limit=25, order_desc=False, channel=None, taglist=[]):

        order = None
        if order_desc:
            order = Clips.first_contact.desc()

        if taglist:
            thing = self.session.query(Clips).\
                        filter(and_(Clips.back_users.any(Users.id == user_id),
                                    Clips.clip_channel_name != channel,
                                    Clips.children.any(Tags.tag.in_(taglist))
                                    )).\
                            order_by(order).limit(limit).all()
        else:
            thing = self.session.query(Clips).\
                        filter(and_(Clips.back_users.any(Users.id == user_id),
                                    Clips.clip_channel_name != channel)).\
                            order_by(order).limit(limit).all()

        return thing, len(thing)


    def get_one(self, user_id, clip_identifier):

        try:
            return self.session.query(Clips).\
                    filter(and_(Clips.back_users.any(Users.id == user_id),
                                Clips.clip_identifier == clip_identifier)).one()
        except:
            return None

    def delete(self, clip):

        try:
            asd = self.session.delete(clip)
            self.session.commit()
            return True, "success"
        except:
            return False, "error"

class Tag:

    def __init__(self, session):

        self.session = session

    def add(self, clip, tag):

        thing = Tags(tag)

        clip.children.append(thing)

        try:
            self.session.commit()
            return True, "success"

        except IntegrityError:
            self.session.rollback()
            return False, "duplicate"

        else:
            self.session.rollback()
            return False, "Unknown"

    def get(self, clip_id, tag):

        try:
            thing = self.session.query(Tags).\
                        filter(and_(Tags.back_clips.any(Clips.id == clip_id),
                                    Tags.tag == tag)).one()
            return thing
        except:
            return None

    def remove(self, clip, tag):

        thing = self.get(clip.id, tag)

        if not thing:
            return False

        else:
            try:
                self.session.delete(thing)
                self.session.commit()
                return True
            except:
                return False

class Sess:

    def __init__(self, session):

        self.session = session

    @commit
    def add(self, session_salt, user_id):

        thing = Sessions(session_salt, user_id)

        self.session.add(thing)

    def get(self, user_id):

        return self.session.query(Sessions).filter(Sessions.user_id == user_id).all()

    def remove_one(self, session_salt):
        self.session.query(Sessions).filter(Sessions.session_salt == session_salt).delete()

    def remove_all(self, user_id):
        self.session.query(Sessions).filter(Sessions.user_id == user_id).delete()

association_table = Table('association_clips', Base.metadata,
    Column('users_id', Integer, ForeignKey('users.id')),
    Column('clips_id', Integer, ForeignKey('clips.id'))
)

association_table_tags = Table('association_tags', Base.metadata,
    Column('clip_id', Integer, ForeignKey('clips.id')),
    Column('tags_id', Integer, ForeignKey('tags.id'))
)

class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(32), nullable=False, unique=True)
    password_hash = Column(String(128), nullable=False)
    password_salt = Column(String(128), nullable=False)
    last_updated = Column(DateTime, nullable=False, default=text('NOW()'), onupdate=text('NOW()'))
    first_contact = Column(DateTime, nullable=False, server_default=text('NOW()'))

    children = relationship("Clips", secondary=association_table, backref="back_users")

    def __init__(self, username, password_salt, password_hash):

        self.username = username
        self.password_hash = password_hash
        self.password_salt = password_salt

class Clips(Base):
    __tablename__ = 'clips'

    id = Column(Integer, primary_key=True)
    clip_channel_name = Column(String(25), nullable=False)
    clip_title = Column(String(100), nullable=False)
    clip_identifier = Column(Text, nullable=False)
    clip_thumbnail = Column(Text, nullable=False)
    last_updated = Column(DateTime, nullable=False, default=text('NOW()'), onupdate=text('NOW()'))
    first_contact = Column(DateTime, nullable=False, server_default=text('NOW()'))

    children = relationship("Tags", secondary=association_table_tags, backref="back_clips")

    def __init__(self, channel_name, clip_title, clip_identifier, clip_thumbnail):

        self.clip_channel_name = channel_name
        self.clip_title = clip_title
        self.clip_identifier = clip_identifier
        self.clip_thumbnail = clip_thumbnail

class Sessions(Base):
    __tablename__ = 'sessions'

    id = Column(Integer, primary_key=True)
    session_salt = Column(String(128), nullable=False)
    user_id = Column(Integer, primary_key=False)
    last_updated = Column(DateTime, nullable=False, default=text('NOW()'), onupdate=text('NOW()'))
    first_contact = Column(DateTime, nullable=False, server_default=text('NOW()'))

    def __init__(self, session_salt, user_id):

        self.session_salt = session_salt
        self.user_id = user_id

class Tags(Base):
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True)
    tag = Column(String(32), nullable=False)
    last_updated = Column(DateTime, nullable=False, default=text('NOW()'), onupdate=text('NOW()'))
    first_contact = Column(DateTime, nullable=False, server_default=text('NOW()'))

    def __init__(self, tag):

        self.tag = tag
