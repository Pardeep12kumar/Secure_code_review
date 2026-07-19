from flask_login import login_required, current_user
from flask import Blueprint, render_template

from flask_login import (
    login_required,
    current_user
)

from models.uploaded_file import UploadedFile
from models.scan_result import ScanResult



main = Blueprint("main", __name__)

@main.route("/")
def home():
    return render_template("index.html")


@main.route("/dashboard")
@login_required
def dashboard():

    uploaded_files = UploadedFile.query.filter_by(
            user_id=current_user.id
    ).order_by(
        UploadedFile.upload_time.desc()
    ).all()

    for file in uploaded_files:
        file.is_scanned = (
            ScanResult.query.filter_by(
                uploaded_file_id=file.id
            ).first() is not None
       )

    total_files = len(uploaded_files)

    scan_results = (
        ScanResult.query
        .join(UploadedFile)
        .filter(UploadedFile.user_id == current_user.id)
        .all()
    )

    total_scans = len(scan_results)

    high = sum(
        1 for result in scan_results
        if result.severity == "High"
    )

    medium = sum(
        1 for result in scan_results
        if result.severity == "Medium"
    )

    low = sum(
        1 for result in scan_results
        if result.severity == "Low"
    )

    return render_template(
        "dashboard.html",
        uploaded_files=uploaded_files,
        total_files=total_files,
        total_scans=total_scans,
        high=high,
        medium=medium,
        low=low
    )


@main.route("/profile")
@login_required
def profile():

    total_files = UploadedFile.query.filter_by(
        user_id=current_user.id
    ).count()

    total_vulnerabilities = ScanResult.query.join(
        UploadedFile
    ).filter(
        UploadedFile.user_id == current_user.id
    ).count()

    return render_template(
        "profile.html",
        total_files=total_files,
        total_vulnerabilities=total_vulnerabilities
    )
