import os

# General
PRODUCT_NAME = "Bisa LSP"
PRODUCT_ENVIRONMENT = "DEV"  # DEV/PROD

IS_USE_VENV = "YES"  # YES/NO
VENV_FOLDER_PATH = os.path.abspath(os.path.join(
    __file__, "../../../venv_app_name")) + "/"  # Just Change value after __file__,

# JWT
JWT_SECRET_KEY = "anaksekolahid"
JWT_HEADER_TYPE = "JWT"

# Database
DB_NAME = "anaksekolah_id"
DB_USER = "root"
DB_PASSWORD = ""
DB_HOST = "localhost"

# URL
BACKEND_BASE_URL = "https://localhost:20000/"

# Folder Path
# 2 variabel dibawah merupakan default logs dan upload (didalam direktori projek)
# 2 variabel dibawah jangan dihapus, jika tidak ingin menggunakan default
# cukup comment 2 variabel dibawah dan buat 2 variabel baru dengan nama yang sama
UPLOAD_FOLDER_PATH = os.path.abspath(
    os.path.join(__file__, "../../upload")) + "/"
LOGS_FOLDER_PATH = os.path.abspath(os.path.join(__file__, "../../logs"))
