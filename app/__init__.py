from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

login_manager.login_view = "auth.login"
login_manager.login_message = "Please login first."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


def create_app():

    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

    # Import database models
    from models.user import User
    from models.uploaded_file import UploadedFile
    from models.scan_result import ScanResult

    # Register blueprints
    from app.routes.main import main
    app.register_blueprint(main)

    from app.routes.auth import auth
    app.register_blueprint(auth)

    from app.routes.upload import upload
    app.register_blueprint(upload)

    # Register upload blueprint (only if app/routes/upload.py exists)
    # from app.routes.upload import upload
    # app.register_blueprint(upload)

    # Register error handlers
    from app.errors import register_error_handlers
    register_error_handlers(app)

    return app
