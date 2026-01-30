def hello(name):
    return f"Hello, {name}!"


@app.route("/users")
def get_users():
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute(query)


class UserService:
    def __init__(self, db):
        self.db = db

    def find_user(self, user_id):
        return self.db.query(f"SELECT * FROM users WHERE id = {user_id}")
