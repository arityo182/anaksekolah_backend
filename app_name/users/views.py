from audioop import cross
from flask import Flask, Blueprint, jsonify, request, make_response, render_template
from flask import current_app as app
from flask_jwt_extended import get_jwt, jwt_required, JWTManager
from flask_cors import cross_origin
from werkzeug.utils import secure_filename
from werkzeug.datastructures import ImmutableMultiDict
from time import gmtime, strftime
import hashlib
import datetime
import requests
import os
import base64
import random
import json
import warnings
import string
import numpy as np
import cv2

from .models import Data

user = Blueprint('user', __name__,
                 static_folder='../../upload/foto_user', static_url_path="/media")

# region ================================= FUNGSI-FUNGSI AREA ==========================================================================

role_group_all = ["mahasiswa", "mentor", "pengajar", "admin"]


def tambahLogs(logs):
    f = open(app.config['LOGS'] + "/" +
             secure_filename(strftime("%Y-%m-%d")) + ".txt", "a")
    f.write(logs)
    f.close()


def save(encoded_data, filename):
    arr = np.fromstring(base64.b64decode(encoded_data), np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_UNCHANGED)
    return cv2.imwrite(filename, img)


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

# endregion ================================= FUNGSI-FUNGSI AREA ===============================================================


# region ================================= MY PROFILE AREA ==========================================================================

# get profile user guru
@user.route('/get_guru_profile', methods=['GET', 'OPTIONS'])
@jwt_required()
@cross_origin()
def get_guru_profile():
    try:

        user_id = str(get_jwt()["user_id"])
        role_desc = str(get_jwt()["role_desc"])

        if role_desc not in role_group_all:
            return permission_failed()

        dt = Data()

        query_temp = """SELECT a.* FROM course a WHERE guru_id = %s """
        values_temp = (user_id, )

        # data course
        course_data = dt.get_data(query_temp, values_temp)
        rowCount = dt.row_count(query_temp, values_temp)

        #check course pada guru_id
        if len(course_data) == 0:
            return jsonify({"status" : "Silakan Buat Course"})
        else :
            course_data = {'data': course_data, 'status_code': 200, 'row_count': rowCount}
        return make_response(jsonify(course_data), 200)
    except Exception as e:
        return bad_request(str(e))

#get profile user siswa
@user.route('/get_siswa_profile', methods=['GET', 'OPTIONS'])
@jwt_required()
@cross_origin()
def get_siswa_profile():
    try:
        user_id = str(get_jwt()["user_id"])
        role_desc = str(get_jwt()["role_desc"])

        if role_desc not in role_group_all:
            return permission_failed()

        dt = Data()

        query_temp = """SELECT a.* FROM course_diambil a WHERE murid = %s """
        values_temp = (user_id, )

        # data course
        course_data = dt.get_data(query_temp, values_temp)
        rowCount = dt.row_count(query_temp, values_temp)

        #check course pada guru_id
        if len(course_data) == 0:
            return jsonify({"status" : "Silakan Beli Course"})
        else :
            course_data = {'data': course_data, 'status_code': 200, 'row_count': rowCount}
        return make_response(jsonify(course_data), 200)
    except Exception as e:
            return bad_request(str(e))






