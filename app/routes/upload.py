import os
import uuid
import csv
from io import StringIO
from flask import Response
from io import BytesIO

from reportlab.lib import colors

from reportlab.lib.styles import getSampleStyleSheet

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph
)

from flask import send_file

from flask import abort
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    url_for
)

from flask_login import (
    login_required,
    current_user
)

from werkzeug.utils import secure_filename
from flask import request
from services.analyzer import CodeAnalyzer

from models.scan_result import ScanResult

from app import db

from app.forms.upload_form import UploadForm

from app.utils.file_utils import (
    allowed_file,
    detect_language
)

from models.uploaded_file import UploadedFile

upload = Blueprint(
    "upload",
    __name__,
    url_prefix="/upload"
)


@upload.route("/", methods=["GET", "POST"])
@login_required
def upload_file():

    form = UploadForm()

    if form.validate_on_submit():

        file = form.source_file.data

        if file:

            filename = secure_filename(file.filename)

            if not allowed_file(
                filename,
                current_app.config["ALLOWED_EXTENSIONS"]
            ):

                flash(
                    "Unsupported file type.",
                    "danger"
                )

                return redirect(
                    url_for("upload.upload_file")
                )

            extension = filename.rsplit(".", 1)[1].lower()

            stored_filename = (
                f"{uuid.uuid4().hex}.{extension}"
            )

            save_path = os.path.join(
                current_app.config["UPLOAD_FOLDER"],
                stored_filename
            )

            file.save(save_path)

            uploaded = UploadedFile(

                user_id=current_user.id,

                original_filename=filename,

                stored_filename=stored_filename,

                language=detect_language(filename)

            )

            db.session.add(uploaded)

            db.session.commit()

            flash(
                "File uploaded successfully.",
                "success"
            )

            return redirect(
                url_for("main.dashboard")
            )

    return render_template(
        "upload.html",
        form=form
    )
@upload.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):

    uploaded_file = UploadedFile.query.get_or_404(file_id)

    if uploaded_file.user_id != current_user.id:
        abort(403)

    file_path = os.path.join(
        current_app.config["UPLOAD_FOLDER"],
        uploaded_file.stored_filename
    )

    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(uploaded_file)
    db.session.commit()

    flash(
        "File deleted successfully.",
        "success"
    )

    return redirect(
        url_for("main.dashboard")
    )



@upload.route("/scan/<int:file_id>")
@login_required
def scan_file(file_id):

    uploaded_file = UploadedFile.query.get_or_404(file_id)

    if uploaded_file.user_id != current_user.id:
        abort(403)

    file_path = os.path.join(
        current_app.config["UPLOAD_FOLDER"],
        uploaded_file.stored_filename
    )

    print("=" * 50)
    print("File:", file_path)

    analyzer = CodeAnalyzer(file_path)

    print("Language:", analyzer.language)

    results = analyzer.analyze()

    print("Results:", results)
    print("Total:", len(results))
    print("=" * 50)

    # Delete previous scan results
    ScanResult.query.filter_by(
        uploaded_file_id=file_id
    ).delete()

    db.session.commit()


    print("Results found:", len(results))
    # Save new scan results
    for result in results:

        print(result)

        scan = ScanResult(
            uploaded_file_id=file_id,
            rule=result["title"],
            severity=result["severity"],
            line=result["line"],
            title=result["title"],
            message=result["message"],
            recommendation=result["recommendation"],
            cwe=result["cwe"],
            owasp=result["owasp"]
        )

        db.session.add(scan)
    print("Pending objects:", len(db.session.new))
    try:
    
        db.session.commit()
        print("✓ Scan results saved successfully.")
    except Exception as e:
        db.session.rollback()
        print("DATABASE ERROR:", e)

    flash(
        f"Scan completed successfully. {len(results)} vulnerabilities found.",
        "success"
    )

    return redirect(
        url_for(
            "upload.scan_results",
            file_id=file_id
        )
    )
@upload.route("/export/csv/<int:file_id>")
@login_required
def export_csv(file_id):

    uploaded_file = UploadedFile.query.get_or_404(file_id)

    if uploaded_file.user_id != current_user.id:
        abort(403)

    results = ScanResult.query.filter_by(
        uploaded_file_id=file_id
    ).all()

    output = StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Line",
        "Severity",
        "Title",
        "Description",
        "Recommendation",
        "CWE",
        "OWASP"
    ])

    for result in results:

        writer.writerow([
            result.line,
            result.severity,
            result.title,
            result.message,
            result.recommendation,
            result.cwe,
            result.owasp
        ])

    output.seek(0)

    return Response(

        output.getvalue(),

        mimetype="text/csv",

        headers={

            "Content-Disposition":
            f"attachment; filename={uploaded_file.original_filename}_report.csv"

        }

    )

@upload.route("/export/pdf/<int:file_id>")
@login_required
def export_pdf(file_id):

    uploaded_file = UploadedFile.query.get_or_404(file_id)

    if uploaded_file.user_id != current_user.id:
        abort(403)

    results = ScanResult.query.filter_by(
        uploaded_file_id=file_id
    ).all()

    buffer = BytesIO()

    document = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "<b>Secure Code View - Security Scan Report</b>",
            styles["Title"]
        )
    )

    elements.append(
        Paragraph(
            f"Filename: {uploaded_file.original_filename}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Language: {uploaded_file.language}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph("<br/>", styles["Normal"])
    )

    data = [[
        "Line",
        "Severity",
        "Title",
        "CWE",
        "OWASP"
    ]]

    for result in results:

        data.append([
            str(result.line),
            result.severity,
            result.title,
            result.cwe,
            result.owasp
        ])

    table = Table(data)

    table.setStyle(

        TableStyle([

            ("BACKGROUND", (0,0), (-1,0), colors.grey),

            ("TEXTCOLOR", (0,0), (-1,0), colors.white),

            ("GRID", (0,0), (-1,-1), 1, colors.black),

            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

            ("BOTTOMPADDING", (0,0), (-1,0), 8),

            ("ALIGN", (0,0), (-1,-1), "CENTER")

        ])

    )

    elements.append(table)

    document.build(elements)

    buffer.seek(0)

    return send_file(

        buffer,

        as_attachment=True,

        download_name=f"{uploaded_file.original_filename}_report.pdf",

        mimetype="application/pdf"

    )

@upload.route("/results/<int:file_id>")
@login_required
def scan_results(file_id):

    uploaded_file = UploadedFile.query.get_or_404(file_id)

    if uploaded_file.user_id != current_user.id:
        abort(403)

    severity = request.args.get("severity")
    search = request.args.get("search")

    query = ScanResult.query.filter_by(
        uploaded_file_id=file_id
    )

    if severity and severity != "All":
        query = query.filter_by(severity=severity)

    if search:
        query = query.filter(
            ScanResult.title.contains(search)
        )

    results = query.all()

    all_results = ScanResult.query.filter_by(
        uploaded_file_id=file_id
    ).all()

    high = sum(1 for r in all_results if r.severity == "High")
    medium = sum(1 for r in all_results if r.severity == "Medium")
    low = sum(1 for r in all_results if r.severity == "Low")

    return render_template(
        "scan_results.html",
        uploaded_file=uploaded_file,
        results=results,
        high=high,
        medium=medium,
        low=low
    )


