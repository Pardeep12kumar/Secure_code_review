from flask_wtf import FlaskForm

from flask_wtf.file import (
    FileField,
    FileRequired
)

from wtforms import SubmitField


class UploadForm(FlaskForm):

    source_file = FileField(
        "Select Source Code File",
        validators=[
            FileRequired(
                message="Please choose a source code file."
            )
        ]
    )

    submit = SubmitField(
        "Upload File"
    )
