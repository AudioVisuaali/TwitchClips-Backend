from flask import Flask, request, jsonify, session, make_response
from utils import headers_check, cookies_check, session_check
from database import Database
import config

database = Database()
database.set_credentials(config.type_, config.username, config.password, config.address, config.database)
database.connect()

app = Flask(__name__)
app.secret_key = config.secret_key
app.config["JSON_SORT_KEYS"] = config.sort_keys

@app.route('/addr', methods=['GET'])
def remote_addr():
    return jsonify({'remote_address': request.remote_addr,"user_agent": request.user_agent.string}), 200

@app.route('/user/create', methods=['GET'])
@headers_check(["username", "password"])
def create_user():

    args = request.args

    state, msg = database.user.create(args["username"], args["password"])

    if not state:
        return jsonify({'error': msg}), 400

    return jsonify({'state': "success"}), 200

@app.route('/user/login', methods=['GET'])
@headers_check(["username", "password"])
def login_user():

    args = request.args

    thing = database.user.login(args["username"], args["password"], request.remote_addr, request.user_agent.string)

    # Must be == False
    if thing == False:
        return jsonify({'error': "Wrong username or password"}), 400

    database.sess.add(thing.salt, thing.user_id)

    resp = jsonify({'login': "success"})
    resp.set_cookie("user", str(thing.user_id))
    resp.set_cookie("session", thing.hash_)

    return resp, 200

@app.route('/user/check_session', methods=['GET'])
@cookies_check(["user", "session"])
def check_session():
    cookies = request.cookies

    remote_addr = request.remote_addr
    user_agent = request.user_agent.string
    user_id = cookies["user"]
    session_hash = cookies["session"]

    state, msg = database.user_logged_in(remote_addr, user_agent, user_id, session_hash)

    if not state:
        return jsonify({'error': msg}), 400

    return jsonify({'session': msg}), 200

@app.route('/user/logout_one', methods=['GET'])
@cookies_check(["session", "user"])
def logout_user():
    cookies = request.cookies

    def create_res(error, state):
        resp = jsonify({'error': error})
        resp.set_cookie("user", expires=0)
        resp.set_cookie("session", expires=0)

        return resp, state

    remote_addr = request.remote_addr
    user_agent = request.user_agent.string

    user = database.user.get_by_id(cookies["user"])

    if not user:
        return create_res("no user", 400)

    sessions = database.sess.get(user.id)

    if not sessions:
        return create_res("no session", 400)

    for session in sessions:

        hash_ = database.user.hash_(remote_addr + user_agent, session.session_salt)

        if hash_ == cookies["session"]:
            database.sess.remove_one(session.session_salt)
            return create_res("removed", 200)

    return create_res("no session", 400)

@app.route('/clip/add', methods=['GET'])
@session_check(database)
@headers_check(["clip_channel_name", "clip_title", "clip_identifier", "clip_thumbnail"])
def clip_Add():

    args = request.args

    user = database.user.get_by_id(request.cookies["user"])

    if not user:
        return jsonify({'error': 'User not found'}), 400

    clip_check = database.clip.get_one(user.id, args["clip_identifier"])

    if clip_check:
        return jsonify({'error': "duplicate"}), 400

    state, error = database.clip.add(user, args["clip_channel_name"], args["clip_title"], args["clip_identifier"], args["clip_thumbnail"])

    if not state:
        return jsonify({'state': error}), 400

    return jsonify({'state': "success"}), 200

@app.route('/clip/get', methods=['GET'])
@session_check(database)
def get_clip():

    args = request.args

    taglist = []

    try:
        limit = int(request.args['limit'])
        if limit > 100:
            limit = 100
    except:
        limit = 25

    user = database.user.get_by_id(request.cookies["user"])

    if not user:
        return jsonify({'error': "User error"}), 400

    clips, amount = database.clip.get(user.id, limit=limit, taglist=taglist)

    things = []
    for clip in clips:
        clip_tags = []
        for tag in clip.children:
            clip_tags.append(tag.tag)
        things.append({'id': clip.id, 'clip_channel_name': clip.clip_channel_name, 'clip_title': clip.clip_title, 'clip_identifier': clip.clip_identifier, 'clip_thumbnail': clip.clip_thumbnail, 'first_contact': clip.first_contact, 'tags': clip_tags})

    return jsonify({'user_id': user.id, 'user_name': user.username, 'clips': things, 'requested_amount': limit, 'substantive_amount': amount, 'state': 'success'})

@app.route('/clip/remove', methods=['GET'])
@session_check(database)
@headers_check(["clip_identifier"])
def clip_remove():

    args = request.args

    user = database.user.get_by_id(request.cookies["user"])

    if not user:
        return jsonify({'error': "User error"}), 400

    clip = database.clip.get_one(user.id, args["clip_identifier"])

    if not clip:
        return jsonify({'error': "Clip error"}), 400

    for tag in clip.children:
        database.tag.remove(clip, tag.tag)

    state, msg = database.clip.delete(clip)

    if not state:
        return jsonify({'error': msg}), 400

    return jsonify({'state': "success"}), 200

@app.route('/tag/add', methods=['GET'])
@session_check(database)
@headers_check(["clip_identifier", "tag"])
def tag_add():

    args = request.args

    user = database.user.get_by_id(request.cookies["user"])

    if not user:
        return jsonify({'error': "User error"}), 400

    clip = database.clip.get_one(user.id, args["clip_identifier"])

    if not clip:
        return jsonify({'error': "Clip error"}), 400

    tag_check = database.tag.get(clip.id, args["tag"])

    if tag_check:
        return jsonify({'error': 'duplicate'}), 400

    state, msg = database.tag.add(clip, args["tag"])

    if state:
        return jsonify({'state': 'success'}), 200

    else:
        return jsonify({'error': msg}), 400

@app.route('/tag/remove', methods=['GET'])
@session_check(database)
@headers_check(["clip_identifier", "tag"])
def tag_remove():

    args = request.args

    user = database.user.get_by_id(request.cookies["user"])

    if not user:
        return jsonify({'error': "User error"}), 400

    clip = database.clip.get_one(user.id, args["clip_identifier"])

    if not clip:
        return jsonify({'error': "Clip error"}), 400

    tag = database.tag.remove(clip, args["tag"])

    if clip:
        return jsonify({'state': "success"}), 200

    else:
        return jsonify({'error': "error"}), 400

if __name__ == '__main__':
    try:
        app.run(debug=config.debug, host=config.app_host)
    except KeyboardInterrupt:
        database.close()
        database.dispose()
