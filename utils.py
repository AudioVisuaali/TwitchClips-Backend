from flask import request, jsonify
from functools import wraps

# Commit database session
def commit(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        original_func = func(self, *args, **kwargs)
        self.session.commit()
        return original_func
    return wrapper

# Check session
def session_check(database):
    def decorator(func):
        @wraps(func)
        def wrapper():

            required = ["user", "session"]

            cookies = request.cookies

            for cookie in cookies:
                if cookie in required:
                    required.remove(cookie)

            if required:
                return jsonify({'error': "missing cookie {}".format(required[0])}), 400

            state, msg = database.user_logged_in(request.remote_addr,
                                                 request.user_agent.string,
                                                 request.cookies["user"],
                                                 request.cookies["session"])

            if not state:
                return jsonify({'error': "log in"}), 400

            return func()
        return wrapper
    return decorator

# Check headers
def headers_check(required):
    def decorator(func):
        @wraps(func)
        def wrapper():

            args = request.args

            for arg in args:
                if arg in required:
                    required.remove(arg)

            if required:
                return jsonify({'error': "missing header {}".format(required[0])}), 400

            return func()
        return wrapper
    return decorator

# Check cookies
def cookies_check(required):
    def decorator(func):
        @wraps(func)
        def wrapper():

            cookies = request.cookies

            for cookie in cookies:
                if cookie in required:
                    required.remove(cookie)

            if required:
                return jsonify({'error': "missing cookie {}".format(required[0])}), 400

            return func()
        return wrapper
    return decorator
