from .app_name import app
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8091, debug=True)
