from werkzeug.security import generate_password_hash, check_password_hash

from app import db
class UserInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=True)
    account = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    roles = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    is_enable = db.Column(db.Boolean , nullable=True, default=True)
    posts = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'account': self.account,
            'roles': self.roles,
            'phone': self.phone,
            'is_enable': self.is_enable,
            'posts':self.posts,
            'department':self.department,
            'avatar':self.avatar,
            # 'password_hash':self.password_hash
        }