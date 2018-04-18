def headers(required):
    def real_decorator(function):
        def wrapper(*args, **kwargs):

            args = request.args

            for arg in args:
                if arg in required:
                    required.remove(arg)

            if required:
                return jsonify({'error': "missing header {}".format(required[0])}), 400

            function(*args, **kwargs)

        return wrapper
    return real_decorator

def commit(func):
    def wrapper(self, *args, **kwargs):
        original_func = func(self, *args, **kwargs)
        self.session.commit()
        return original_func
    return wrapper
