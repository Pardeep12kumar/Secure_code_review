from app import db


class ScanResult(db.Model):

    __tablename__ = "scan_results"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    uploaded_file_id = db.Column(
        db.Integer,
        db.ForeignKey("uploaded_files.id"),
        nullable=False
    )

    rule = db.Column(
        db.String(150),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    line = db.Column(
        db.Integer,
        nullable=False
    )

    title = db.Column(
        db.String(200),
        nullable=False
    )

    message = db.Column(
        db.Text,
        nullable=False
    )

    recommendation = db.Column(
        db.Text,
        nullable=False
    )

    cwe = db.Column(
        db.String(30)
    )

    owasp = db.Column(
        db.String(50)
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    def __repr__(self):

        return (
            f"<ScanResult {self.rule}>"
        )
