from flask import current_app
from sqlalchemy import false
from sqlalchemy.exc import NoResultFound
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models.userinfoModel import UserInfo

# services = services
def create_user( account, password):
    # 检查用户是否已存在
    existing_user = UserInfo.query.filter_by(account=account).first()
    if existing_user:
        return None,"Account already exists."
    try:
        new_user = UserInfo(
            # name=name,
            account=account,
            password_hash=generate_password_hash(password),
            avatar="http://localhost:5000/static/img/defalutavatar.png",
            roles="normal",
            # phone=phone
        )
        db.session.add(new_user)
        db.session.commit()
        return new_user.to_dict(),None
    except Exception as e:
        current_app.logger.error(f"Error during user verification: {e}")
        return None,f"Error during user verification: {e}"
def get_user_by_id(user_id):
    try:
        user = UserInfo.query.get(user_id)
        if user:
            return user.to_dict()
        return None
    except Exception as e:
        current_app.logger.error(f"Error fetching user by ID {user_id}: {e}")
        return None
def get_passhash_by_id(user_id):
    try:
        user = UserInfo.query.get(user_id)
        if user:
            return user.to_dict()['password_hash']
        return None
    except Exception as e:
        current_app.logger.error(f"Error fetching user by ID {user_id}: {e}")
        return None
def get_all_users():
    try:
        users = UserInfo.query.all()
        return [user.to_dict() for user in users]
    except Exception as e:
        current_app.logger.error(f"Error fetching all users: {e}")
        return []
def update_user(user_id, name=None, account=None, password=None, roles=None, phone=None,avatar=None,posts=None,department=None):
    try:
        user = UserInfo.query.get(user_id)
        if not user:
            return None
        if name is not None:
            user.name = name
        if account is not None:
            user.account = account
        if password is not None:
            user.set_password(password)
        if roles is not None:
            user.roles = roles
        if phone is not None:
            user.phone = phone
        if avatar is not None:
            user.avatar = avatar
        if posts is not None:
            user.posts = posts
        if department is not None:
            user.department = department
        db.session.commit()
        return user.to_dict()
    except Exception as e:
        db.session.rollback()  # 发生异常时回滚事务
        current_app.logger.error(f"Error updating user with ID {user_id}: {e}")
        return None
def delete_user(user_id):
    try:
        user = UserInfo.query.get(user_id)
        if not user:
            return False
        db.session.delete(user)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()  # 发生异常时回滚事务
        current_app.logger.error(f"Error deleting user with ID {user_id}: {e}")
        return False
def verify_user(account, password):
    """验证用户凭据"""
    try:
        # 查询用户
        user = UserInfo.query.filter_by(account=account).first()
        # 验证用户和密码
        if user and user.check_password(password):
            if user.is_enable!=1:
                current_app.logger.warning(f"User {account} is forbidden to login.")
                return "forbidden"
            current_app.logger.info(f"User {account} logged in successfully.")
            return user
        else:
            current_app.logger.warning(f"Failed login attempt for account: {account}")
            return None
    except Exception as e:
        current_app.logger.error(f"Error during user verification: {e}")
        return None

def update_isEnable_status(user_id, is_enable):
    try:
        # 查询用户是否存在
        # user = db.query(UserInfo).filter(UserInfo.id == user_id).one()
        user = UserInfo.query.get(user_id)
        if not user:
            return False
        user.is_enable = is_enable
        db.session.commit()
        return True  # 操作成功
    except NoResultFound:
        # 如果没有找到用户，记录错误日志并返回 False
        current_app.logger.error(f"User with id {user_id} not found.")
        return False
    except Exception as e:
        # 其他异常处理，比如数据库错误等
        db.session.rollback()
        current_app.logger.error(f"Error updating user status: {e}")
        return False
def check_old_pass(user_id, old_password):
    try:
        # 获取用户信息
        user = UserInfo.query.get(user_id)
        if not user.to_dict():
            current_app.logger.warning(f"User with ID {user_id} not found.")
            return False
        # 检查旧密码是否匹配
        hashed_password = user.to_dict().get('password')
        if not hashed_password:
            current_app.logger.warning(f"Password not found for user with ID {user_id}.")
            return False

        is_correct = check_password_hash(hashed_password, old_password)

        if not is_correct:
            current_app.logger.info(f"Incorrect old password provided for user with ID {user_id}.")

        return is_correct

    except Exception as e:
        current_app.logger.error(f"Error checking old password for user ID {user_id}: {e}")
        return False