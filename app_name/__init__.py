from .users.views import user
from .course.views import course
from .transaksi.views import transaksi
from .tryout.views import tryout
from .ekstrakulikuler.views import ekstrakulikuler
from flask import Flask, make_response
from json import dumps, loads
from datetime import timedelta
import json
from urllib import response
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.flask_client import OAuth
from . import config as CFG
from flask import Flask, Blueprint, jsonify, request, make_response, render_template, session, url_for, redirect
from werkzeug.utils import secure_filename
from flask_cors import cross_origin
from flask_jwt_extended import get_jwt, jwt_required, JWTManager, create_access_token, set_access_cookies, unset_access_cookies, unset_jwt_cookies
from flask import Flask, Blueprint
from flask import current_app as app
from flask_jwt_extended import JWTManager
from flask import Flask, Blueprint, jsonify, request, make_response, render_template
from flask_jwt_extended import get_jwt, jwt_required, JWTManager
from flask_cors import cross_origin
from werkzeug.utils import secure_filename
from werkzeug.datastructures import ImmutableMultiDict
import hashlib
import datetime
import random
import string
from time import strftime
import os


from.users.models import Data

app = Flask(__name__, static_url_path=None)  # panggil modul flask

# Flask JWT Extended Configuration
app.config['SECRET_KEY'] = CFG.JWT_SECRET_KEY
app.config['JWT_HEADER_TYPE'] = CFG.JWT_HEADER_TYPE
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(
    days=1)  # 1 hari token JWT expired
jwt = JWTManager(app)

# Application Configuration
app.config['PRODUCT_ENVIRONMENT'] = CFG.PRODUCT_ENVIRONMENT
app.config['BACKEND_BASE_URL'] = CFG.BACKEND_BASE_URL

app.config['JWT_TOKEN_LOCATION'] = ['headers', 'query_string']
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]
app.config["JWT_TOKEN_LOCATION"] = ['headers']
app.config["JWT_HEADER_NAME"] = 'Authorization'
app.config["JWT_HEADER_TYPE"] = 'Bearer'

app.config['LOGS'] = CFG.LOGS_FOLDER_PATH

# UPLOAD FOLDER PATH
UPLOAD_FOLDER_PATH = CFG.UPLOAD_FOLDER_PATH

# Cek apakah Upload Folder Path sudah diakhiri dengan slash atau belum
if UPLOAD_FOLDER_PATH[-1] != "/":
    UPLOAD_FOLDER_PATH = UPLOAD_FOLDER_PATH + "/"

app.config['UPLOAD_FOLDER_FOTO_USER'] = UPLOAD_FOLDER_PATH+"foto_user/"
app.config['UPLOAD_FOLDER_FOTO_TEMPAT_UJI_KOMPETENSI'] = UPLOAD_FOLDER_PATH + \
    "lokasi/foto_tempat_uji_kompetensi/"

# Create folder if doesn't exist
list_folder_to_create = [
    app.config['LOGS'],
    app.config['UPLOAD_FOLDER_FOTO_USER'],
    app.config['UPLOAD_FOLDER_FOTO_TEMPAT_UJI_KOMPETENSI']
]
for x in list_folder_to_create:
    if os.path.exists(x) == False:
        os.makedirs(x)

# endregion >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CONFIGURATION <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


# region >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> FUNCTION AREA <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
@app.route('/')
def index():
    return "Hello, World!"


def permission_failed():
    return make_response(jsonify({'error': 'Permission Failed', 'status_code': 403}), 403)


def request_failed():
    return make_response(jsonify({'error': 'Request Failed', 'status_code': 403}), 403)


def defined_error(description, error="Defined Error", status_code=499):
    return make_response(jsonify({'description': description, 'error': error, 'status_code': status_code}), status_code)


def parameter_error(description, error="Parameter Error", status_code=400):
    if app.config['PRODUCT_ENVIRONMENT'] == "DEV":
        return make_response(jsonify({'description': description, 'error': error, 'status_code': status_code}), status_code)
    else:
        return make_response(jsonify({'description': "Terjadi Kesalahan Sistem", 'error': error, 'status_code': status_code}), status_code)


def bad_request(description):
    if app.config['PRODUCT_ENVIRONMENT'] == "DEV":
        # Development
        return make_response(jsonify({'description': description, 'error': 'Bad Request', 'status_code': 400}), 400)
    else:
        # Production
        return make_response(jsonify({'description': "Terjadi Kesalahan Sistem", 'error': 'Bad Request', 'status_code': 400}), 400)


def randomString(stringLength):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def random_string_number_only(stringLength):
    letters = string.digits
    return ''.join(random.choice(letters) for i in range(stringLength))


def tambahLogs(logs):
    f = open(app.config['LOGS'] + "/" +
             secure_filename(strftime("%Y-%m-%d")) + ".txt", "a")
    f.write(logs)
    f.close()

# endregion ================================= FUNGSI-FUNGSI AREA ===============================================================

# halaman awal


@app.route("/")
def home():
    return "MSIB BISA AI Backend"

# register admin


@app.route('/admin_register/<user_id>', methods=['PUT', 'POST'])
@cross_origin()
def admin_register(user_id):
    hasil = {"status": "gagal menambah admin"}

    try:
        dt = Data()
        query_update = "UPDATE user SET user_id = %s "
        values_update = (user_id, )
        status_id = "admin"
        query_update += ", email = %s "
        values_update += (status_id, )
        query_update += " WHERE user_id = %s "
        values_update += (user_id, )
        dt.insert_data_last_row(query_update, values_update)
        query = "INSERT INTO admin (user_id) VALUES (%s)"
        values = (user_id, )
        dt.insert_data(query, values)
        hasil = {"status": "berhasil menambah admin"}
        return make_response(hasil)
    except Exception as e:
        return bad_request(str(e))

# login admin


@app.route('/admin_login', methods=['POST'])
@cross_origin()
def admin_login():
    ROUTE_NAME = request.path

    data = request.json
    if "email" not in data:
        return parameter_error("Missing username in Request Body")
    if "password" not in data:
        return parameter_error("Missing username in Request Body")

    email = data["email"]
    password = data["password"]

    email = email.lower()
    password_enc = hashlib.md5(password.encode(
        'utf-8')).hexdigest()  # Convert password to md5

    # Check credential in database
    dt = Data()
    query1 = """SELECT a.user_id, a.email, a.password, a.status_user,
            b.user_id AS admin FROM user a LEFT JOIN admin b
            ON a.user_id = b.user_id WHERE a.is_active = 11 AND  
            a.email = %s """
    values = (email, )
    data_user = dt.get_data(query1, values)
    if len(data_user) == 0:
        return defined_error("Email not Registered or not Active", "Invalid Credential", 401)
    data_user = data_user[0]
    db_id_user = data_user["user_id"]
    db_password = data_user["password"]
    db_email = data_user['email']
    db_status = data_user['status_user']

    if password_enc != db_password:
        return defined_error("Wrong Password", "Invalid Credential", 401)

    role_desc = "admin"

    jwt_payload = {
        "user_id": db_id_user,
        "role_desc": role_desc,
        "email": db_email,
        "status_id": db_status
    }

    access_token = create_access_token(
        email, additional_claims=jwt_payload)

    # Update waktu terakhir login customer
    query_temp = "UPDATE user SET last_login = now() WHERE user_id = %s"
    values_temp = (db_id_user, )
    dt.insert_data(query_temp, values_temp)

    try:
        logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
            " - user_id = "+str(db_id_user) + \
            " - roles = "+str(role)+"\n"
    except Exception as e:
        logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S")) + \
            " - "+ROUTE_NAME+" - user_id = NULL - roles = NULL\n"
    # tambahLogs(logs)

    return jsonify(access_token=access_token)


# register user


@app.route("/users_register", methods=['POST'])
@cross_origin()
def register():
    ROUTE_NAME = request.path

    try:
        dt = Data()
        data = request.json

        # Check mandatory data
        if "nama" not in data:
            return parameter_error("Missing nama in Request Body")
        if "email" not in data:
            return parameter_error("Missing email in Request Body")
        if "no_tlp" not in data:
            return parameter_error("Missing Nomor Telepon in request body")
        if "password" not in data:
            return parameter_error("Missing password in Request Body")
        if "status_id" not in data:
            return parameter_error("Missing status user in request body")

        # mendapat data dari request body
        nama = request.json.get('nama')
        email = request.json.get('email')
        no_tlp = request.json.get('no_tlp')
        password = request.json.get('password')
        status_id = request.json.get('status_id')

        # check if Email already used or not
        query_temp = "SELECT email FROM user WHERE email = %s"
        values_temp = (email, )
        if len(dt.get_data(query_temp, values_temp)) != 0:
            return defined_error("Email Already Registered")

        # Convert password to MD5
        pass_ency = hashlib.md5(password.encode("utf-8")).hexdigest()

        # Insert to table user
        query = "INSERT into user (nama, email, no_telp, password, status_user) VALUES (%s, %s, %s, %s, %s)"
        values = (nama, email, no_tlp, pass_ency, status_id)
        user_id = dt.insert_data_last_row(query, values)

        if status_id == "guru":
            # Insert to table customer
            query2 = "INSERT INTO guru (user_id) VALUES (%s)"
            values2 = (user_id, )
            dt.insert_data(query2, values2)

            hasil = "Silakan Login"

            try:
                logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                    " - user_id = "+str(user_id)+" - roles = "+str(role)+"\n"
            except Exception as e:
                logs = secure_filename(strftime(
                    "%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME+" - user_id = NULL - roles = NULL\n"
                # tambahLogs(logs)

            return make_response(jsonify({'status_code': 200, 'description': hasil}), 200)
        else:
            # Insert to table customer
            query2 = "INSERT INTO murid (user_id) VALUES (%s)"
            values2 = (user_id, )
            dt.insert_data(query2, values2)

            hasil = "Silakan Login"

            try:
                logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                    " - user_id = "+str(user_id)+" - roles = "+str(role)+"\n"
            except Exception as e:
                logs = secure_filename(strftime(
                    "%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME+" - user_id = NULL - roles = NULL\n"
                # tambahLogs(logs)
            return make_response(jsonify({'status_code': 200, 'description': hasil}), 200)

    except Exception as e:
        return bad_request(str(e))


# Login User
@app.route("/users_login", methods=["POST"])
@cross_origin()
def login_users():
    ROUTE_NAME = request.path

    data = request.json
    if "email" not in data:
        return parameter_error("Missing username in Request Body")
    if "password" not in data:
        return parameter_error("Missing username in Request Body")

    email = data["email"]
    password = data["password"]

    email = email.lower()
    password_enc = hashlib.md5(password.encode(
        'utf-8')).hexdigest()  # Convert password to md5

    # Check credential in database
    dt = Data()
    query1 = """SELECT a.user_id, a.email, a.password, a.status_user,
            b.user_id AS murid, c.user_id AS guru FROM user a LEFT JOIN murid b
            ON a.user_id = b.user_id LEFT JOIN guru c ON a.user_id = c.user_id
            WHERE a.is_active = 11 AND  
            a.email = %s """
    # query = """ SELECT b.id_user, b.email, b.password, b.status_id
    #         FROM murid a LEFT JOIN users b ON a.id_user=b.id_user
    #         WHERE a.is_aktif = 1 AND a.is_delete != 1 AND b.status_user = 11 AND b.is_delete != 1 AND
    #         b.email = %s """
    values = (email, )
    data_user = dt.get_data(query1, values)
    if len(data_user) == 0:
        return defined_error("Email not Registered or not Active", "Invalid Credential", 401)
    data_user = data_user[0]
    db_id_user = data_user["user_id"]
    db_password = data_user["password"]
    db_email = data_user['email']
    db_status = data_user['status_user']

    if password_enc != db_password:
        return defined_error("Wrong Password", "Invalid Credential", 401)

    if email == db_email and db_status == "guru":
        role = 21
        role_desc = "user"

        jwt_payload = {
            "user_id": db_id_user,
            "role": role,
            "role_desc": role_desc,
            "email": email,
            "status_id": db_status
        }

        access_token = create_access_token(
            email, additional_claims=jwt_payload)

        # Update waktu terakhir login customer
        query_temp = "UPDATE user SET last_login = now() WHERE user_id = %s"
        values_temp = (db_id_user, )
        dt.insert_data(query_temp, values_temp)

        try:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                " - user_id = "+str(db_id_user)+" - roles = "+str(role)+"\n"
        except Exception as e:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S")) + \
                " - "+ROUTE_NAME+" - user_id = NULL - roles = NULL\n"
        # tambahLogs(logs)

    else:
        role = 21
        role_desc = "user"

        jwt_payload = {
            "user_id": db_id_user,
            "role": role,
            "role_desc": role_desc,
            "email": email,
            "status_id": db_status
        }

        access_token = create_access_token(
            email, additional_claims=jwt_payload)

        # Update waktu terakhir login customer
        query_temp = "UPDATE user SET last_login = now() WHERE user_id = %s"
        values_temp = (db_id_user, )
        dt.insert_data(query_temp, values_temp)

        try:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                " - user_id = "+str(db_id_user) + \
                " - roles = "+str(role)+"\n"
        except Exception as e:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S")) + \
                " - "+ROUTE_NAME+" - user_id = NULL - roles = NULL\n"
        # tambahLogs(logs)

    return jsonify(access_token=access_token)


# Login Register user google
oauth = OAuth(app)

app.config['SECRET_KEY'] = "anaksekolahid"
app.config['GOOGLE_CLIENT_ID'] = "780995326706-72v4csud2t1mhlc1k283cb3pte72p7f5.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

google = oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    # This is only needed if using openId to fetch user info
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",

)


@app.route('/login/google')
# @cross_origin()
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

# Google authorize route


@app.route('/login/google/authorize')
def google_authorize():
    ROUTE_NAME = request.path
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo').json()
    email = resp['email'].lower()
    name = resp['name']
    id = resp['id']
    status_id = "murid"

    dt = Data()
    query_temp = "SELECT email, user_id FROM user WHERE email = %s"
    values_temp = (email, )
    data_user = dt.get_data(query_temp, values_temp)
    data_user = data_user[0]
    user_id = data_user["user_id"]
    if len(dt.get_data(query_temp, values_temp)) != 0:
        role = 21
        role_desc = "user"
        jwt_payload = {
            "user_id": id,
            "role": role,
            "role_desc": role_desc,
            "email": email,
            "status_id": status_id
        }

        access_token = create_access_token(
            email, additional_claims=jwt_payload)
        # Update waktu terakhir login customer

        query_temp = "UPDATE user SET last_login = now() WHERE user_id = %s"
        values_temp = (user_id, )
        dt.insert_data(query_temp, values_temp)

        try:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                " - user_id = "+str(id)+" - roles = "+str(role)+"\n"
        except Exception as e:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S")) + \
                " - "+ROUTE_NAME+" - user_id = NULL - roles = NULL\n"

        return jsonify(access_token=access_token)
    else:
        # Insert to table user
        query = "INSERT into user (nama, email, status_user, password) VALUES (%s, %s, %s, %s)"
        values = (name, email, status_id, id)
        id_user = dt.insert_data_last_row(query, values)

        # masukan data ke user
        query2 = "INSERT INTO murid (user_id) VALUES (%s)"
        values2 = (id_user, )
        dt.insert_data(query2, values2)

        try:
            logs = secure_filename(strftime("%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME + \
                " - user_id = "+str(id_user)+" - roles = "+str(role)+"\n"
        except Exception as e:
            logs = secure_filename(strftime(
                "%Y-%m-%d %H:%M:%S"))+" - "+ROUTE_NAME+" - user_id = NULL - roles = NULL\n"
        # tambahLogs(logs)
        # return make_response(jsonify({'status_code': 200, 'description': hasil}), 200)

        role = 21
        role_desc = "user"
        jwt_payload = {
            "user_id": id,
            "role": role,
            "role_desc": role_desc,
            "email": email,
            "status_id": status_id
        }

        access_token = create_access_token(
            email, additional_claims=jwt_payload)

        return jsonify(access_token=access_token)


# # Gak jadi
# @app.route('/logout', methods=['DELETE'])
# @jwt_required()
# def logout():
#     user = get_jwt(
#         "id_user",
#         "role",
#         "role_desc",
#         "email"
#     )
#     set().add(str(user))
#     return jsonify({"msg": "Successfully logged out."})


# fungsi error handle Halaman Tidak Ditemukan


@app.errorhandler(404)
@cross_origin()
def not_found(error):
    return make_response(jsonify({'error': 'Tidak Ditemukan', 'status_code': 404}), 404)

# fungsi error handle Halaman internal server error


@app.errorhandler(500)
@cross_origin()
def not_found(error):
    return make_response(jsonify({'error': 'Error Server', 'status_code': 500}), 500)

# endregion >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ERROR HANDLER AREA <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


# --------------------- REGISTER BLUEPRINT ------------------------

app.register_blueprint(user, url_prefix='/users')
app.register_blueprint(course, url_prefix='/course')
app.register_blueprint(ekstrakulikuler, url_prefix='/ekstrakulikuler')
app.register_blueprint(tryout, url_prefix='/tryout')
app.register_blueprint(transaksi, url_prefix='/transaksi')

# --------------------- END REGISTER BLUEPRINT ------------------------
