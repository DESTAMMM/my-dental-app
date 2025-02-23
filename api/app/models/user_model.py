import json
from flask_login import UserMixin
from werkzeug.security import  generate_password_hash
from app.database import db

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __init__(self, username, password, role=["user"]):
        self.username = username
        self.role = json.dumps(role)
        self.password_hash = generate_password_hash(password)

    def save(self):
        db.session.add(self)
        db.session.commit()
    
    @staticmethod
    def get_all():
        return User.query.all()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def has_role(self, role):
        roles = json.loads(self.role)
        return role in roles
       
    @staticmethod
    def find_by_username(username):
        return User.query.filter_by(username=username).first()