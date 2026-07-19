from app import db


class UploadedFile(db.Model):

    __tablename__ = "uploaded_files"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    original_filename = db.Column(
        db.String(255),
        nullable=False
    )

    stored_filename = db.Column(
        db.String(255),
        nullable=False,
        unique=True
    )

    language = db.Column(
        db.String(30),
        nullable=False
    )

    upload_time = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )


    def __repr__(self):

        return (
            f"<UploadedFile "
            f"{self.original_filename}>"
        )
