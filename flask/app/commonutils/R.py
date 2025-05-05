from flask import jsonify


class R:
    @staticmethod
    def ok(message="成功", data=None):
        return R(True, 200, message, data)

    @staticmethod
    def error(message="失败", data=None, code=400):
        return R(False, code, message, data)

    @staticmethod
    def info(message="提示", data=None):
        return R(False, 222, message, data)
    def __init__(self, success=True, code=200, message="成功", data=None):
        self.success = success
        self.code = code
        self.message = message
        self.data = data if data is not None else {}

    def set_message(self, message):
        self.message = message
        return self

    def set_code(self, code):
        self.code = code
        return self

    def set_data(self, data):
        self.data = data
        return self

    def to_json(self):
        response_data = {
            'success': self.success,
            'code': self.code,
            'message': self.message,
            'data': self.data
        }
        return jsonify(response_data), self.code if not self.success else 200